use clap::Clap;
use goblin::container::Ctx;
use goblin::elf::{Header, ProgramHeader, SectionHeader};
use goblin::error;
use scroll::Pwrite;
use std::collections::HashMap;
use std::fs;
use std::io::prelude::*;

#[derive(Clap, Debug)]
struct Opts {
    #[clap(short)]
    input: String,
    #[clap(short)]
    output: String,
}
#[derive(Debug)]
struct AllocatedSection<'a> {
    section: &'a SectionHeader,
    address: usize,
}

// Given a list of section headers, return a map of original section indices to the corresponding allocated section
// as well as a total size of the binary.
fn allocate_sections<'a>(
    ctx: Ctx,
    section_headers: &'a [SectionHeader],
) -> (HashMap<usize, AllocatedSection<'a>>, usize) {
    let alloc_secs: Vec<(usize, &'a SectionHeader)> = section_headers
        .iter()
        .enumerate()
        .filter(|(_i, sec)| {
            sec.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0 && sec.sh_size > 0
        })
        .collect();
    // Afaict, we do not need to worry about alignment for program and section headers.
    let mut offset = Header::size(ctx)
        + alloc_secs.len() * (ProgramHeader::size(ctx) + SectionHeader::size(ctx));
    let allocated_secs: HashMap<usize, AllocatedSection<'a>> = alloc_secs
        .into_iter()
        .map(|(index, section)| {
            let align = 2usize.pow(section.sh_addralign as u32);
            let address = (offset + align) / align * align;
            assert!(section.sh_size > 0);
            offset = address + section.sh_size as usize;
            let sec = AllocatedSection {
                section: section,
                address: address,
            };
            (index, sec)
        })
        .collect();
    (allocated_secs, offset)
}

fn entry_point(syms: &goblin::elf::Symtab, strtab: &goblin::strtab::Strtab) -> Option<goblin::elf::Sym> {
    syms.iter().find(|sym| strtab.get_unsafe(sym.st_name) == Some("_start"))
}

fn main() -> Result<(), error::Error> {
    let opts = Opts::parse();
    let buffer = fs::read(opts.input)?;
    let elf = goblin::elf::Elf::parse(&buffer)?;

    // mapping from index of reloc section to sh_info, i.e., the associated section the relocation applies to.
    let reloc_mapping: HashMap<usize, usize> = elf
        .shdr_relocs
        .iter()
        .map(|(i, _)| {
            let x: &SectionHeader = elf.section_headers.get(*i).unwrap();
            (*i, x.sh_info as usize)
        })
        .collect();

    let ctx = goblin::container::Ctx::new(
        goblin::container::Container::Big,
        goblin::container::Endian::Little,
    );
    let (allocated_secs, size) = allocate_sections(ctx, &elf.section_headers);

    let mut vec: Vec<u8> = Vec::new();
    vec.resize(size, 0);

    let entry_sym = entry_point(&elf.syms, &elf.strtab).unwrap();
    let entry_loc = allocated_secs.get(&entry_sym.st_shndx).unwrap().address as u64 + entry_sym.st_value;


    let elf_header = goblin::elf::header::Header {
        e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: goblin::elf::header::ET_EXEC,
        e_machine: 0x3e,
        e_version: 0x1,
        e_entry: entry_loc,
        e_phoff: goblin::elf::header::Header::size(ctx) as u64,
        e_shoff: goblin::elf::header::Header::size(ctx) as u64
            + allocated_secs.len() as u64 * goblin::elf::ProgramHeader::size(ctx) as u64,
        e_flags: 0,
        e_ehsize: 0,
        e_phentsize: goblin::elf::program_header::ProgramHeader::size(ctx) as u16,
        e_phnum: allocated_secs.len() as u16,
        e_shentsize: goblin::elf::section_header::SectionHeader::size(ctx) as u16,
        e_shnum: allocated_secs.len() as u16,
        e_shstrndx: 0,
    };
    &mut vec[..].pwrite_with(elf_header, 0, scroll::Endian::Little)?;
    for (i, sec) in allocated_secs.values().enumerate() {
        let ph_header = ProgramHeader {
            p_type: goblin::elf::program_header::PT_LOAD,
            p_flags: goblin::elf::program_header::PF_R,
            p_offset: sec.address as u64,
            p_vaddr: sec.address as u64,
            p_paddr: sec.address as u64,
            p_filesz: sec.section.sh_size,
            p_memsz: sec.section.sh_size,
            p_align: sec.section.sh_addralign,
        };
        &mut vec[..].pwrite_with(
            ph_header,
            Header::size(ctx) + i * ProgramHeader::size(ctx),
            ctx,
        )?;
        if sec.section.sh_size > 0 {
            vec.pwrite_with(
                &buffer[sec.section.sh_offset as usize .. (sec.section.sh_offset + sec.section.sh_size - 1) as usize],
                sec.address,
                ()
            )?;
        }
    }
    for (i, sec) in allocated_secs.values().enumerate() {
        let sh_header = SectionHeader {
            sh_name: 0, // TODO
            sh_addralign: sec.section.sh_addralign,
            sh_offset: sec.address as u64,
            sh_size: sec.section.sh_size,
            sh_type: sec.section.sh_type,
            sh_addr: sec.address as u64,
            sh_entsize: sec.section.sh_entsize,
            sh_flags: sec.section.sh_flags,
            sh_link: sec.section.sh_link,
            sh_info: sec.section.sh_info,
        };
        vec.pwrite_with(
            sh_header,
            Header::size(ctx)
                + allocated_secs.len() * ProgramHeader::size(ctx)
                + i * SectionHeader::size(ctx),
            ctx,
        )?;
    }

    // apply relocation
    for (sh_idx, reloc_sec) in elf.shdr_relocs {
        let sec = allocated_secs.get(&reloc_mapping[&sh_idx]).unwrap();
        for reloc in reloc_sec.iter() {
            assert_eq!(reloc.r_type, goblin::elf::reloc::R_X86_64_PC32);
            let a = reloc.r_addend.unwrap();
            let sym = elf.syms.get(reloc.r_sym).unwrap();
            let sym_sec = allocated_secs.get(&sym.st_shndx).unwrap();
            let s: i64 = sym_sec.address as i64 + sym.st_value as i64;
            let p = sec.address as i64 + reloc.r_offset as i64;
            let r: i64 = s + a - p;
            vec.pwrite_with(r as i32, p as usize, ctx.le)?;
        }
    }

    // Write to file
    let mut buffer = std::io::BufWriter::new(fs::File::create(&opts.output)?);
    buffer.write_all(&mut vec)?;
    buffer.flush()?;

    Ok(())
}

use clap::Clap;
use goblin::elf::header::Header;
use goblin::elf::program_header::ProgramHeader;
use goblin::elf::section_header::SectionHeader;
use goblin::{error, Object};
use scroll::Pwrite;
use std::fs;
use std::io::prelude::*;

#[derive(Clap, Debug)]
struct Opts {
    #[clap(short)]
    input: String,
    #[clap(short)]
    output: String,
}
struct AllocatedSection {
    section: SectionHeader,
    address: usize,
}
fn main() -> Result<(), error::Error> {
    let opts = Opts::parse();
    let buffer = fs::read(opts.input)?;
    let elf = goblin::elf::Elf::parse(&buffer)?;

    let alloc_secs: Vec<goblin::elf::SectionHeader> = elf
        .section_headers
        .into_iter()
        .filter(|sec| sec.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0 && sec.sh_size > 0)
        .collect();

    let ctx = goblin::container::Ctx::new(
        goblin::container::Container::Big,
        goblin::container::Endian::Little,
    );
    let mut vec: Vec<u8> = Vec::new();
    let header_size = Header::size(ctx) + alloc_secs.len() * (goblin::elf::ProgramHeader::size(ctx) + goblin::elf::SectionHeader::size(ctx));

    let allocated_secs: Vec<AllocatedSection> = alloc_secs
        .into_iter()
        .scan(header_size, |state, section| {
            let align = (2 as usize).pow(section.sh_addralign as u32);
            let address = (*state + align) / align * align as usize;
            *state = address + section.sh_size as usize + 1;
            Some(AllocatedSection {
                section: section,
                address: address,
            })
        })
        .collect();

    {
        let last = &allocated_secs.last().unwrap();
        vec.resize(header_size + last.address + last.section.sh_size as usize, 0);
    }
    let elf_header = goblin::elf::header::Header {
        e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: goblin::elf::header::ET_EXEC,
        e_machine: 0x3e,
        e_version: 0x1,
        e_entry: allocated_secs.first().unwrap().address as u64,
        e_phoff: goblin::elf::header::Header::size(ctx) as u64,
        e_shoff: goblin::elf::header::Header::size(ctx) as u64 + allocated_secs.len() as u64 * goblin::elf::ProgramHeader::size(ctx) as u64,
        e_flags: 0,
        e_ehsize: 0,
        e_phentsize: goblin::elf::program_header::ProgramHeader::size(ctx) as u16,
        e_phnum: allocated_secs.len() as u16,
        e_shentsize: goblin::elf::section_header::SectionHeader::size(ctx) as u16,
        e_shnum: allocated_secs.len() as u16,
        e_shstrndx: 0,
    };
    &mut vec[..].pwrite_with(elf_header, 0, scroll::Endian::Little)?;
    for (i, sec) in allocated_secs.iter().enumerate() {
        let ph_header = ProgramHeader {
            p_type: goblin::elf::program_header::PT_LOAD,
            p_flags: goblin::elf::program_header::PF_X
                | goblin::elf::program_header::PF_R
                | goblin::elf::program_header::PF_W,
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
            &mut vec[sec.address..sec.address + sec.section.sh_size as usize - 1].copy_from_slice(
                &buffer[sec.section.sh_offset as usize
                    ..sec.section.sh_offset as usize + sec.section.sh_size as usize - 1],);
        }
    }
    for (i, sec) in allocated_secs.iter().enumerate() {
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
        &mut vec[..].pwrite_with(
            sh_header,
            Header::size(ctx) + allocated_secs.len() * ProgramHeader::size(ctx) + i * SectionHeader::size(ctx),
            ctx,
        )?;
    }


    let mut buffer = std::io::BufWriter::new(fs::File::create(&opts.output)?);
    buffer.write_all(&mut vec[..])?;
    buffer.flush()?;

    let new_buffer = fs::read(&opts.output)?;
    let new_elf = goblin::elf::Elf::parse(&new_buffer)?;
    println!("{:#?}", new_elf);
    Ok(())
}

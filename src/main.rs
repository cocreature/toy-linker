use clap::Clap;
use goblin::container::Ctx;
use goblin::elf::{Header, ProgramHeader, SectionHeader};
use goblin::error;
use scroll::Pwrite;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::io::prelude::*;

#[derive(Clap, Debug)]
struct Opts {
    #[clap(short)]
    input: Vec<String>,
    #[clap(short)]
    output: String,
}

#[derive(Debug)]
struct InputSection<'a> {
    file_idx: usize,
    shdr_idx: goblin::elf::ShdrIdx,
    section: SectionHeader,
    // Inline name for debugging
    name: &'a str,
}

#[derive(Debug)]
struct RelocationSection<'a> {
    applies_to_file: usize,
    applies_to_sec: goblin::elf::ShdrIdx,
    relocations: goblin::elf::RelocSection<'a>,
}

#[derive(Debug)]
struct Symbol<'a> {
    name: &'a str,
    sym: goblin::elf::Sym,
}

#[derive(Debug)]
struct SymbolTable<'a> {
    by_file: HashMap<usize, (goblin::elf::Symtab<'a>, goblin::strtab::Strtab<'a>)>,
    globals: HashMap<&'a str, (usize, usize)>,
}

impl<'a> SymbolTable<'a> {
    fn new() -> Self {
        SymbolTable {
            by_file: HashMap::new(),
            globals: HashMap::new(),
        }
    }
    fn insert(
        &mut self,
        file_idx: usize,
        symtab: goblin::elf::Symtab<'a>,
        strtab: goblin::strtab::Strtab<'a>,
    ) -> () {
        use goblin::elf::section_header::*;
        use goblin::elf::sym::*;
        for (sym_idx, sym) in symtab.iter().enumerate() {
            if st_bind(sym.st_info) == STB_GLOBAL
                && sym.st_shndx != usize::try_from(SHN_UNDEF).unwrap()
            {
                let name = strtab.get_unsafe(sym.st_name).unwrap();
                self.globals.insert(name, (file_idx, sym_idx));
            }
        }
        self.by_file.insert(file_idx, (symtab, strtab));
    }
    fn get(&self, file_idx: usize, sym_idx: usize) -> goblin::elf::Sym {
        let symtab = &self.by_file.get(&file_idx).unwrap().0;
        symtab.get(sym_idx).unwrap()
    }
}

#[derive(Debug)]
struct Input<'a> {
    file_buffers: Vec<&'a [u8]>,
    code_sections: Vec<InputSection<'a>>,
    data_sections: Vec<InputSection<'a>>,
    ro_data_sections: Vec<InputSection<'a>>,
    reloc_sections: Vec<RelocationSection<'a>>,
    symtab: SymbolTable<'a>,
}

#[derive(Debug)]
struct OutputSection<'a> {
    address: usize,
    input_section: InputSection<'a>,
}

#[derive(Debug)]
struct Output<'a> {
    file_buffers: Vec<&'a [u8]>,
    code_sections: Vec<OutputSection<'a>>,
    data_sections: Vec<OutputSection<'a>>,
    ro_data_sections: Vec<OutputSection<'a>>,
    // Map from file (idx, section idx) to the offset in the output file
    section_offsets: HashMap<(usize, goblin::elf::ShdrIdx), usize>,
    reloc_sections: Vec<RelocationSection<'a>>,
    symtab: SymbolTable<'a>,
    total_size: usize,
}

impl<'a> Input<'a> {
    fn new() -> Self {
        Input {
            file_buffers: vec![],
            code_sections: vec![],
            data_sections: vec![],
            ro_data_sections: vec![],
            reloc_sections: vec![],
            symtab: SymbolTable::new(),
        }
    }

    fn process_object_file(&mut self, file: &'a [u8]) -> Result<(), error::Error> {
        use goblin::elf::section_header::*;
        let elf = goblin::elf::Elf::parse(file)?;
        let file_idx = self.file_buffers.len();
        self.file_buffers.push(file);
        for (i, reloc) in elf.shdr_relocs {
            let sec = &elf.section_headers[i];
            let applies_to_sec = usize::try_from(sec.sh_info).unwrap();
            let reloc_sec: RelocationSection = RelocationSection {
                applies_to_file: file_idx,
                applies_to_sec,
                relocations: reloc,
            };
            self.reloc_sections.push(reloc_sec);
        }
        self.symtab.insert(file_idx, elf.syms, elf.strtab);
        for (idx, sec) in elf.section_headers.into_iter().enumerate() {
            let name = elf.shdr_strtab.get_unsafe(sec.sh_name).unwrap();
            match sec.sh_type {
                SHT_PROGBITS => {
                    let input_sec = InputSection {
                        file_idx,
                        shdr_idx: idx,
                        section: sec,
                        name: name,
                    };
                    if input_sec.section.sh_flags == u64::from(SHF_ALLOC | SHF_EXECINSTR) {
                        self.code_sections.push(input_sec);
                    } else if input_sec.section.sh_flags == u64::from(SHF_ALLOC | SHF_WRITE) {
                        self.data_sections.push(input_sec);
                    } else if input_sec.section.sh_flags & !u64::from(SHF_MERGE | SHF_STRINGS)
                        == u64::from(SHF_ALLOC)
                    {
                        // We don’t merge sections or treat specially so everything that is read only is identical to us.
                        self.ro_data_sections.push(input_sec);
                    } else if input_sec.section.sh_flags & u64::from(SHF_ALLOC)
                        == u64::from(SHF_ALLOC)
                    {
                        // Panic on unknown alloc flags, we ignore non-alloc sections.
                        panic!("Unknown flags {} in {}", input_sec.section.sh_flags, name);
                    }
                }
                SHT_NULL | SHT_NOBITS | SHT_RELA | SHT_SYMTAB | SHT_STRTAB => {}
                unknown => panic!(
                    "Unknown section type: {} ({})",
                    goblin::elf::section_header::sht_to_str(unknown),
                    unknown
                ),
            }
        }
        Ok(())
    }
    fn allocate(self, ctx: Ctx) -> Output<'a> {
        let mut section_offsets = HashMap::new();
        let header_size = Header::size(ctx);
        // code, data, ro_data
        let num_prog_headers = 3;
        // TODO For now, we omit section headers but they would be useful for debugging.
        // let num_sec_headers = self.code_sections.len() + self.data_sections.len() + self.ro_data_sections.len();
        let mut offset = header_size + ProgramHeader::size(ctx) * num_prog_headers;
        let mut code_sections = Vec::new();
        let mut data_sections = Vec::new();
        let mut ro_data_sections = Vec::new();
        offset = align(offset, PAGE_SIZE);
        for sec in self.code_sections {
            offset = align(offset, usize::try_from(sec.section.sh_addralign).unwrap());
            code_sections.push(OutputSection {
                address: offset,
                input_section: sec,
            });
            let sec = &code_sections.last().unwrap().input_section;
            section_offsets.insert((sec.file_idx, sec.shdr_idx), offset);
            offset += usize::try_from(sec.section.sh_size).unwrap();
        }
        offset = align(offset, PAGE_SIZE);
        for sec in self.data_sections {
            offset = align(offset, usize::try_from(sec.section.sh_addralign).unwrap());
            data_sections.push(OutputSection {
                address: offset,
                input_section: sec,
            });
            let sec = &data_sections.last().unwrap().input_section;
            section_offsets.insert((sec.file_idx, sec.shdr_idx), offset);
            offset += usize::try_from(sec.section.sh_size).unwrap();
        }
        offset = align(offset, PAGE_SIZE);
        for sec in self.ro_data_sections {
            offset = align(offset, usize::try_from(sec.section.sh_addralign).unwrap());
            ro_data_sections.push(OutputSection {
                address: offset,
                input_section: sec,
            });
            let sec = &ro_data_sections.last().unwrap().input_section;
            section_offsets.insert((sec.file_idx, sec.shdr_idx), offset);
            offset += usize::try_from(sec.section.sh_size).unwrap();
        }
        Output {
            file_buffers: self.file_buffers,
            reloc_sections: self.reloc_sections,
            code_sections,
            data_sections,
            ro_data_sections,
            section_offsets,
            total_size: offset,
            symtab: self.symtab,
        }
    }
}

struct SegmentInfo {
    size: usize,
    offset: usize,
}

fn prog_header_offset(i: usize, ctx: Ctx) -> usize {
    Header::size(ctx) + i * ProgramHeader::size(ctx)
}

fn segment_info(sections: &[OutputSection]) -> SegmentInfo {
    if sections.len() == 0 {
        SegmentInfo { size: 0, offset: 0 }
    } else {
        let first = sections.first().unwrap();
        let last = sections.last().unwrap();
        SegmentInfo {
            size: last.address + usize::try_from(last.input_section.section.sh_size).unwrap()
                - first.address,
            offset: first.address,
        }
    }
}

fn prog_header(info: SegmentInfo) -> ProgramHeader {
    let offset = u64::try_from(info.offset).unwrap();
    let size = u64::try_from(info.size).unwrap();
    ProgramHeader {
        p_type: goblin::elf::program_header::PT_LOAD,
        p_flags: 0,
        p_offset: offset,
        p_vaddr: offset,
        p_paddr: offset,
        p_filesz: size,
        p_memsz: size,
        p_align: u64::try_from(PAGE_SIZE).unwrap(),
    }
}

impl<'a> Output<'a> {
    fn write(&self, buf: &mut [u8], ctx: Ctx) -> Result<(), error::Error> {
        use goblin::elf::program_header::*;
        let (entry_file_idx, entry_sym_idx) = self.symtab.globals.get("_start").unwrap();
        let entry_sym = self.symtab.get(*entry_file_idx, *entry_sym_idx);
        let entry = u64::try_from(
            *self
                .section_offsets
                .get(&(*entry_file_idx, entry_sym.st_shndx))
                .unwrap(),
        )
        .unwrap()
            + entry_sym.st_value;
        let elf_header = Header {
            e_type: goblin::elf::header::ET_EXEC,
            e_machine: goblin::elf::header::EM_X86_64,
            e_entry: entry,
            e_phoff: u64::try_from(Header::size(ctx)).unwrap(),
            e_phnum: 3,
            ..Header::new(ctx)
        };
        buf.pwrite_with(elf_header, 0, ctx.le)?;

        let code_info = segment_info(&self.code_sections);
        let data_info = segment_info(&self.data_sections);
        let ro_data_info = segment_info(&self.ro_data_sections);

        let code_header = ProgramHeader {
            p_flags: PF_R | PF_X,
            ..prog_header(code_info)
        };
        buf.pwrite_with(code_header, prog_header_offset(0, ctx), ctx)?;
        let data_header = ProgramHeader {
            p_flags: PF_R | PF_W,
            ..prog_header(data_info)
        };
        buf.pwrite_with(data_header, prog_header_offset(1, ctx), ctx)?;
        let ro_data_header = ProgramHeader {
            p_flags: PF_R,
            ..prog_header(ro_data_info)
        };
        buf.pwrite_with(ro_data_header, prog_header_offset(2, ctx), ctx)?;
        for secs in [
            &self.code_sections,
            &self.data_sections,
            &self.ro_data_sections,
        ]
        .iter()
        {
            for sec in *secs {
                let input_sec = &sec.input_section.section;
                let offset = usize::try_from(input_sec.sh_offset).unwrap();
                let size = usize::try_from(input_sec.sh_size).unwrap();
                let file_buf = self.file_buffers[sec.input_section.file_idx];
                buf.pwrite_with(&file_buf[offset..offset + size], sec.address, ())?;
            }
        }
        Ok(())
    }
    fn relocate(&self, buf: &mut [u8], ctx: Ctx) -> Result<(), error::Error> {
        use goblin::elf::header::EM_X86_64;
        use goblin::elf::reloc::*;
        for reloc_sec in &self.reloc_sections {
            let sec_offset =
                self.section_offsets[(&(reloc_sec.applies_to_file, reloc_sec.applies_to_sec))];
            for reloc in reloc_sec.relocations.iter() {
                match reloc.r_type {
                    R_X86_64_PC32 => {
                        let a = reloc.r_addend.unwrap();
                        let sym = self.symtab.get(reloc_sec.applies_to_file, reloc.r_sym);
                        let sym_sec_offset = self
                            .section_offsets
                            .get(&(reloc_sec.applies_to_file, sym.st_shndx))
                            .unwrap();
                        let s = sym_sec_offset + usize::try_from(sym.st_value).unwrap();
                        let p = sec_offset + usize::try_from(reloc.r_offset).unwrap();
                        let r: i64 = i64::try_from(s).unwrap() + i64::try_from(a).unwrap()
                            - i64::try_from(p).unwrap();
                        buf.pwrite_with(i32::try_from(r).unwrap(), p, ctx.le)?;
                    }
                    R_X86_64_PLT32 => {
                        let a = reloc.r_addend.unwrap();
                        let sym = self.symtab.get(reloc_sec.applies_to_file, reloc.r_sym);
                        let sym_name = self
                            .symtab
                            .by_file
                            .get(&reloc_sec.applies_to_file)
                            .unwrap()
                            .1
                            .get_unsafe(sym.st_name)
                            .unwrap();
                        let (file_idx, sym_idx) = self.symtab.globals.get(sym_name).unwrap();
                        let sym = self.symtab.get(*file_idx, *sym_idx);
                        let sym_sec_offset = self
                            .section_offsets
                            .get(&(*file_idx, sym.st_shndx))
                            .unwrap();
                        let l = sym_sec_offset + usize::try_from(sym.st_value).unwrap();
                        let p = sec_offset + usize::try_from(reloc.r_offset).unwrap();
                        let r: i64 = i64::try_from(l).unwrap() + i64::try_from(a).unwrap()
                            - i64::try_from(p).unwrap();
                        buf.pwrite_with(i32::try_from(r).unwrap(), p, ctx.le)?;
                    }
                    unknown => panic!(
                        "Unsupported relocation type: {} ({})",
                        r_to_str(unknown, EM_X86_64),
                        unknown
                    ),
                }
            }
        }
        Ok(())
    }
}

const PAGE_SIZE: usize = 4096;

fn align(offset: usize, align: usize) -> usize {
    let r = offset % align;
    if r == 0 {
        offset
    } else {
        offset - r + align
    }
}

fn run(opts: Opts) -> Result<(), error::Error> {
    let buffers: Vec<Vec<u8>> = opts
        .input
        .iter()
        .map(|file| fs::read(file).unwrap())
        .collect();
    let mut input = Input::new();
    for buffer in &buffers {
        input.process_object_file(&buffer)?;
    }

    let ctx = goblin::container::Ctx::new(
        goblin::container::Container::Big,
        goblin::container::Endian::Little,
    );

    let output = input.allocate(ctx);

    let mut output_vec = Vec::new();
    output_vec.resize(output.total_size, 0);

    output.write(&mut output_vec, ctx)?;
    output.relocate(&mut output_vec, ctx)?;

    let exe_path = std::path::Path::new(&opts.output);
    let exe_file = fs::File::create(exe_path)?;

    let mut buffer = std::io::BufWriter::new(&exe_file);
    buffer.write_all(&mut output_vec)?;
    buffer.flush()?;

    use std::os::unix::fs::PermissionsExt;

    let metadata = &exe_file.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    exe_file.set_permissions(permissions)?;

    Ok(())
}

fn main() -> Result<(), error::Error> {
    let opts = Opts::parse();
    run(opts)
}

#[test]
fn link_example() -> Result<(), error::Error> {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempdir::TempDir;
    let tmp_dir = TempDir::new("test")?;
    fn gcc(out_dir: &Path, file: &Path) -> Result<PathBuf, error::Error> {
        let out = out_dir.join(file.with_extension("o"));
        let output = Command::new("gcc").args(&[
            "-nostdlib",
            "-Wno-main",
            "-Wall",
            "-Werror",
            "-o",
            out.to_str().unwrap(),
            "-c",
            Path::new("examples").join(file).to_str().unwrap(),
        ]).output()?;
        assert!(output.status.success());
        Ok(out)
    }
    
    let main_o = gcc(tmp_dir.path(), Path::new("main.c"))?;
    let lib_o = gcc(tmp_dir.path(), Path::new("lib.c"))?;
    let exe = tmp_dir.path().join("main");
    run(Opts { input: vec![main_o, lib_o].iter().map(|s| String::from(s.to_str().unwrap())).collect(), output: String::from(exe.to_str().unwrap()) })?;
    let output = Command::new(exe).output()?;
    assert_eq!(output.status.code(), Some(42));
    let out = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(out, "Hello world\nwuhu\n");
    Ok(())
}

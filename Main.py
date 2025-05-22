import pefile
from capstone import *

def is_avx_prefix(byte):
    return byte in (0xC4, 0xC5, 0x62)

def analyze_pe_avx(filename):
    pe = pefile.PE(filename)
    
    # Определяем режим дизассемблирования: 64-бит или 32-бит
    md_mode = CS_MODE_64 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else CS_MODE_32
    
    md = Cs(CS_ARCH_X86, md_mode)
    md.detail = True

    print(f"=== Анализ файла: {filename} ===")
    print(f"Архитектура: {'x64' if md_mode == CS_MODE_64 else 'x86'}")
    print("=== Выгрузка и анализ секций ===")

    avx_found = False

    for section in pe.sections:
        sec_name = section.Name.decode(errors='ignore').rstrip('\x00')
        size_raw = section.SizeOfRawData
        virt_addr = section.VirtualAddress
        virt_size = section.Misc_VirtualSize

        print(f"Секция {sec_name} выгружена, размер: {size_raw} байт")
        print(f"  Виртуальный адрес: 0x{virt_addr:x}")
        print(f"  Виртуальный размер: {virt_size} байт")
        print(f"  Размер в файле: {size_raw} байт")

        if size_raw > 0:
            data = section.get_data()
            print(f"  Первые 16 байт: {' '.join(f'{b:02x}' for b in data[:16])}")
        else:
            print(f"  Первые 16 байт:")

        print(f"=== Дизассемблирование секции {sec_name} (первые 20 инструкций) ===")
        
        if size_raw == 0:
            print("============================================================")
            continue
        
        base_addr = pe.OPTIONAL_HEADER.ImageBase + virt_addr

        count = 0
        for insn in md.disasm(data, base_addr):
            if count >= 20:
                break
            print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            count += 1
        
        # Поиск AVX/AVX2 инструкций в секции
        for insn in md.disasm(data, base_addr):
            if len(insn.bytes) > 0 and is_avx_prefix(insn.bytes[0]):
                if not avx_found:
                    print("\n=== Найдены AVX/AVX2 инструкции ===")
                    avx_found = True
                print(f"0x{insn.address:x} [{sec_name}]: {insn.mnemonic} {insn.op_str}")

        print("============================================================")

    if not avx_found:
        print("AVX/AVX2 инструкции не найдены во всех секциях.")
    else:
        print("\nАнализ AVX/AVX2 завершён.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Использование: python3 analyze_avx.py <имя_файла.exe>")
        sys.exit(1)

    analyze_pe_avx(sys.argv[1])

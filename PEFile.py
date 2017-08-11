from collections import OrderedDict


def bytes2int(bstr):
    return int(bstr[::-1].hex(), 16)


def read_str(file, offset):
    temp_offset = file.tell()
    file.seek(offset)
    bstr = b""
    while True:
        temp = file.read(1)
        bstr += temp
        if bytes2int(temp) == 0:
            file.seek(temp_offset)
            return bstr


class PEFile:
    __slots__ = ('file',
                 'IMAGE_DOS_HEADER',
                 'DOS_STUB',
                 'IMAGE_NT_HEADERS',
                 'IMAGE_SECTION_HEADER',
                 'IMAGE_IMPORT_DESCRIPTOR',
                 'IMAGE_EXPORT_DIRECTORY',
                 'DOS_FILE',
                 'PE32PLUS',
                 'EAT'
     )

    def __init__(self, path):
        self.file = open(path, mode='rb')
        self.IMAGE_DOS_HEADER = OrderedDict({
            'e_magic': 2,
            'e_cblp': 2,
            'e_cp': 2,
            'e_crlc': 2,
            'e_cparhdr': 2,
            'e_minalloc': 2,
            'e_maxalloc': 2,
            'e_ss': 2,
            'e_sp': 2,
            'e_csum': 2,
            'e_ip': 2,
            'e_cs': 2,
            'e_lfarlc': 2,
            'e_ovno': 2,
            'e_res': [],
            'e_oemid': 2,
            'e_oeminfo': 2,
            'e_res2': [],
            'e_lfanew': 4
        })
        self.DOS_STUB = b""
        self.IMAGE_NT_HEADERS = OrderedDict({
            'Sinature': 4,
            'IMAGE_FILE_HEADER': OrderedDict({
                'Machine': 2,
                'NumberOfSections': 2,
                'TimeDateStamp': 4,
                'PointerToSymbolTable': 4,
                'NumberOfSymbols': 4,
                'SizeOfOptionalHeader': 2,
                'Characteristics': 2
            }),
            'IMAGE_OPTIONAL_HEADER32': OrderedDict({
                'Magic': 2,
                'MajorLinkerVersion': 1,
                'MinorLinkerVersion': 1,
                'SizeOfCode': 4,
                'SizeOfInitializedData': 4,
                'SizeOfUninitializedData': 4,
                'AddressOfEntryPoint': 4,
                'BaseOfCode': 4,
                'BaseOfData': 4,
                'ImageBase': 4,
                'SectionAlignment': 4,
                'FileAlignment': 4,
                'MajorOperatingSystemVersion': 2,
                'MinorOperatingSystemVersion': 2,
                'MajorImageVersion': 2,
                'MinorImageVersion': 2,
                'MajorSubsystemVersion': 2,
                'MinorSubsystemVersion': 2,
                'Win32VersionValue': 4,
                'SizeOfImage': 4,
                'SizeOfHeaders': 4,
                'CheckSum': 4,
                'Subsystem': 2,
                'DllCharacteristics': 2,
                'SizeOfStackReserve': 4,
                'SizeOfStackCommit': 4,
                'SizeOfHeapReserve': 4,
                'SizeOfHeapCommit': 4,
                'LoaderFlags': 4,
                'NumberOfRvaAndSizes': 4,
                'DataDirectory': []
            })
        })
        self.IMAGE_SECTION_HEADER = []
        self.IMAGE_IMPORT_DESCRIPTOR = []
        self.IMAGE_EXPORT_DIRECTORY = OrderedDict({
            'Characteristics': 4,
            'TimeDataStamp': 4,
            'MajorVersion': 2,
            'MinorVersion': 2,
            'Name': 4,
            'Base': 4,
            'NumberOfFunctions': 4,
            'NumberOfNames': 4,
            'AddressOfFunctions': 4,
            'AddressOfNames': 4,
            'AddressOfNameOrdinals': 4
        })
        self.DOS_FILE = False
        self.PE32PLUS = False
        self.EAT = True
        return

    def __rva2raw(self, rva):
        for section in self.IMAGE_SECTION_HEADER:
            section_offset = bytes2int(section['VirtualAddress'])
            section_size = bytes2int(section['Misc'])
            if section_offset <= rva <= section_offset + section_size:
                return rva - section_offset + bytes2int(section['PointerToRawData'])
        else:
            return -1

    def __bytes2raw(self, bytestr):
        return self.__rva2raw(bytes2int(bytestr))

    def __read_dos_header(self):
        for key, value in self.IMAGE_DOS_HEADER.items():
            if key == 'e_res':
                for i in range(4):
                    self.IMAGE_DOS_HEADER['e_res'].append(self.file.read(2))
            elif key == 'e_res2':
                for i in range(10):
                    self.IMAGE_DOS_HEADER['e_res2'].append(self.file.read(2))
            else:
                self.IMAGE_DOS_HEADER[key] = self.file.read(value)
        return

    def __read_dos_stub(self):
        nt_offset = bytes2int(self.IMAGE_DOS_HEADER['e_lfanew'])
        current_offset = self.file.tell()
        if nt_offset > current_offset:
            self.DOS_STUB = self.file.read(nt_offset - current_offset)
        return

    def __read_nt_file_header(self):
        for key, value in self.IMAGE_NT_HEADERS['IMAGE_FILE_HEADER'].items():
            self.IMAGE_NT_HEADERS['IMAGE_FILE_HEADER'][key] = self.file.read(value)
        return

    def __read_nt_optional_header32(self):
        for key, value in self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32'].items():
            if value:
                self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32'][key] = self.file.read(value)
            else:
                for i in range(bytes2int(self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32']['NumberOfRvaAndSizes'])):
                    self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32'][key].append(OrderedDict({
                        'VirtualAddress': self.file.read(4),
                        'Size': self.file.read(4)
                    }))
        return

    def __read_section_header(self):
        for i in range(bytes2int(self.IMAGE_NT_HEADERS['IMAGE_FILE_HEADER']['NumberOfSections'])):
            self.IMAGE_SECTION_HEADER.append(OrderedDict({
                'Name': self.file.read(8),
                'Misc': self.file.read(4),
                'VirtualAddress': self.file.read(4),
                'SizeOfRawData': self.file.read(4),
                'PointerToRawData': self.file.read(4),
                'PointerToRelocations': self.file.read(4),
                'PoniterToLinenumbers': self.file.read(4),
                'NumberOfRelocations': self.file.read(2),
                'NumberOfLinenumbers': self.file.read(2),
                'Characteristics': self.file.read(4)
            }))
        return

    def __read_import_descriptor(self):
        original_offset = self.file.tell()
        start_offset = self.__bytes2raw(
            self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32']['DataDirectory'][1]['VirtualAddress']
        )
        self.file.seek(start_offset)
        while True:
            temp = OrderedDict({
                'OriginalFirstThunk': self.file.read(4),
                'TimeDateStamp': self.file.read(4),
                'ForwardChain': self.file.read(4),
                'Name': self.file.read(4),
                'FirstThunk': self.file.read(4),
            })
            for key, value in temp.items():
                if bytes2int(value) != 0:
                    temp['INT'] = []
                    temp['IAT'] = []
                    self.IMAGE_IMPORT_DESCRIPTOR.append(temp)
                    break
            else:
                self.file.seek(original_offset)
                return

    def __read_library(self):
        original_offset = self.file.tell()
        for library in self.IMAGE_IMPORT_DESCRIPTOR:
            int_offset = self.__bytes2raw(library['OriginalFirstThunk'])
            if int_offset == -1: # upx compress OriginalFirstThunk is 0
                int_offset = self.__bytes2raw(library['FirstThunk'])
            if int_offset == -1:
                return
            self.file.seek(int_offset)
            while True:
                fun_rav = self.file.read(4)
                if bytes2int(fun_rav) != 0:
                    temp_offset = self.file.tell()
                    fun_offset = self.__bytes2raw(fun_rav)
                    self.file.seek(fun_offset)
                    hint = self.file.read(2)
                    library['INT'].append(OrderedDict({
                        'FunctionRav': fun_rav,
                        'Hint': hint,
                        'Name': read_str(self.file, self.file.tell())
                    }))
                    self.file.seek(temp_offset)
                else:
                    break
            iat_offset = self.__bytes2raw(library['FirstThunk'])
            self.file.seek(iat_offset)
            while True:
                fun_addr = self.file.read(4)
                if bytes2int(fun_addr) != 0:
                    library['IAT'].append(fun_addr)
                else:
                    break
        self.file.seek(original_offset)
        return

    def __read_export_directory(self):
        original_offset = self.file.tell()
        start_offset = self.__bytes2raw(
            self.IMAGE_NT_HEADERS['IMAGE_OPTIONAL_HEADER32']['DataDirectory'][0]['VirtualAddress']
        )
        if start_offset == -1:
            self.EAT = False
            return
        self.file.seek(start_offset)
        for key, value in self.IMAGE_EXPORT_DIRECTORY.items():
            self.IMAGE_EXPORT_DIRECTORY[key] = self.file.read(value)
        self.IMAGE_EXPORT_DIRECTORY['name'] = read_str(self.file,
                                                       self.__bytes2raw(self.IMAGE_EXPORT_DIRECTORY['Name'])
                                                       )
        self.IMAGE_EXPORT_DIRECTORY['FunctionsAddress'] = []
        self.file.seek(self.__bytes2raw(self.IMAGE_EXPORT_DIRECTORY['AddressOfFunctions']))
        for i in range(bytes2int(self.IMAGE_EXPORT_DIRECTORY['NumberOfFunctions'])):
            self.IMAGE_EXPORT_DIRECTORY['FunctionsAddress'].append(self.file.read(4))
        self.IMAGE_EXPORT_DIRECTORY['NameOrdinals'] = []
        self.file.seek(self.__bytes2raw(self.IMAGE_EXPORT_DIRECTORY['AddressOfNameOrdinals']))
        for i in range(bytes2int(self.IMAGE_EXPORT_DIRECTORY['NumberOfNames'])):
            self.IMAGE_EXPORT_DIRECTORY['NameOrdinals'].append(self.file.read(2))
        self.IMAGE_EXPORT_DIRECTORY['Names'] = []
        self.file.seek(self.__bytes2raw(self.IMAGE_EXPORT_DIRECTORY['AddressOfNames']))
        for i in range(bytes2int(self.IMAGE_EXPORT_DIRECTORY['NumberOfNames'])):
            name_addr = self.file.read(4)
            fun_name = read_str(self.file, self.__bytes2raw(name_addr))
            self.IMAGE_EXPORT_DIRECTORY['Names'].append((name_addr, fun_name))
        self.file.seek(original_offset)

    def readheader(self):
        self.__read_dos_header()
        self.__read_dos_stub()
        if bytes2int(self.IMAGE_DOS_HEADER['e_lfanew']) == 0:
            self.DOS_FILE = True  # object file?
            return
        self.IMAGE_NT_HEADERS['Sinature'] = self.file.read(4)
        self.__read_nt_file_header()
        if bytes2int(self.IMAGE_NT_HEADERS['IMAGE_FILE_HEADER']['SizeOfOptionalHeader']) != 224:
            self.PE32PLUS = True
            return
        self.__read_nt_optional_header32()
        self.__read_section_header()
        self.__read_import_descriptor()
        self.__read_library()
        self.__read_export_directory()
        self.file.close()
        return

import ctypes,sys
IMAGE_DOS_SIGNATURE = 23117 #MZ
IMAGE_NT_SIGNATURE = 17744 #PE
IMAGE_ORDINAL_FLAG32 = 2147483648
#STRUCT DEFINE START
class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [('VirtualAddress', ctypes.c_int),
                ('Size', ctypes.c_int)]
class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    _fields_ =[('OriginalFirstThunk',ctypes.c_int),
               ('TimeDateStamp',ctypes.c_int),
               ('ForwarderChain',ctypes.c_int),
               ('Name',ctypes.c_int),
               ('FirstThunk',ctypes.c_int)]
class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [('Name',ctypes.c_byte * 8 ),
                ('Misc',ctypes.c_int),
                ('VirtualAddress',ctypes.c_int),
                ('SizeOfRawData',ctypes.c_int),
                ('PointerToRawData',ctypes.c_int),
                ('PointerToRelocations',ctypes.c_int),
                ('PointerToLinenumbers',ctypes.c_int),
                ('NumberOfRelocations',ctypes.c_short),
                ('NumberOfLinenumbers',ctypes.c_short),
                ('Characteristics',ctypes.c_int)]
class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_=[('e_magic',ctypes.c_short),
              ('e_cblp', ctypes.c_short),
              ('e_cp', ctypes.c_short),
              ('e_crlc', ctypes.c_short),
              ('e_cparhdr', ctypes.c_short),
              ('e_minalloc', ctypes.c_short),
              ('e_maxalloc', ctypes.c_short),
              ('e_ss', ctypes.c_short),
              ('e_sp', ctypes.c_short),
              ('e_csum', ctypes.c_short),
              ('e_ip', ctypes.c_short),
              ('e_cs', ctypes.c_short),
              ('e_lfarlc', ctypes.c_short),
              ('e_ovno', ctypes.c_short),
              ('e_res', ctypes.c_short * 4 ),
              ('e_oemid',ctypes.c_short),
              ('e_oeminfo', ctypes.c_short),
              ('e_res2', ctypes.c_short * 10),
              ('e_lfanew', ctypes.c_int),]
class IMAGE_OPTIONAL_HEADER(ctypes.Structure):
    _fields_=[('Magic',ctypes.c_short),
              ('MajorLinkerVersion',ctypes.c_byte),
              ('MinorLinkerVersion',ctypes.c_byte),
              ('SizeOfCode',ctypes.c_int),
              ('SizeOfInitializedData',ctypes.c_int),
              ('SizeOfUninitializedData',ctypes.c_int),
              ('AddressOfEntryPoint',ctypes.c_int),
              ('BaseOfCode',ctypes.c_int),
              ('BaseOfData',ctypes.c_int),
              ('ImageBase',ctypes.c_int),
              ('SectionAlignment',ctypes.c_int),
              ('FileAlignment',ctypes.c_int),
              ('MajorOperatingSystemVersion',ctypes.c_short),
              ('MinorOperatingSystemVersion',ctypes.c_short),
              ('MajorImageVersion',ctypes.c_short),
              ('MinorImageVersion',ctypes.c_short),
              ('MajorSubsystemVersion',ctypes.c_short),
              ('MinorSubsystemVersion',ctypes.c_short),
              ('Win32VersionValue',ctypes.c_int),
              ('SizeOfImage',ctypes.c_int),
              ('SizeOfHeaders',ctypes.c_int),
              ('CheckSum',ctypes.c_int),
              ('Subsystem',ctypes.c_short),
              ('DllCharacteristics',ctypes.c_short),
              ('SizeOfStackReserve',ctypes.c_int),
              ('SizeOfStackCommit',ctypes.c_int),
              ('SizeOfHeapReserve',ctypes.c_int),
              ('SizeOfHeapCommit',ctypes.c_int),
              ('LoaderFlags',ctypes.c_int),
              ('NumberOfRvaAndSizes',ctypes.c_int),
              ('DataDirectory',IMAGE_DATA_DIRECTORY * 15 )]
class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_=[('Machine',ctypes.c_short),
              ('NumberOfSections',ctypes.c_short),
              ('TimeDateStamp',ctypes.c_int),
              ('PointerToSymbolTable',ctypes.c_int),
              ('NumberOfSymbols',ctypes.c_int),
              ('SizeOfOptionalHeader',ctypes.c_short),
              ('Characteristics',ctypes.c_short)]
class IMAGE_NT_HEADERS(ctypes.Structure):
    _fields_=[('Signature',ctypes.c_int),
              ('FileHeader', IMAGE_FILE_HEADER),
              ('OptionalHeader',IMAGE_OPTIONAL_HEADER)]
#STRUCT DEFINE END
def __CreateBlackByteArry(num):
    tmp = (ctypes.c_byte * num)()
    for i in range(num):
        tmp[i] = ctypes.c_byte(0)
    return tmp
def __IntToC_ByteArray(ints):
    buff = (ctypes.c_byte * 4)()
    buff[3]=  ctypes.c_byte ((ints & 0xFF000000)>>24)
    buff[2] = ctypes.c_byte((ints & 0x00FF0000) >>16)
    buff[1] = ctypes.c_byte((ints & 0x0000FF00) >>8)
    buff[0] = ctypes.c_byte(((ints & 0x000000FF)))
    return buff
def __StringToC_ByteArray(str,fill=False):
    if fill == True:
        s = 0
        tmps = (ctypes.c_byte * 8)()
        for i in str:
            s += 1
            #print(s,ord(i))
            tmps[s] = ord(i)

        return tmps
    else:
        tmps = (ctypes.c_byte * len(str))()
        s = 0
        for i in str:
            tmps[s] = ctypes.c_byte(ord(i))
            s += 1
        return tmps
    return tmps
def IATHOOK(DATA,DllFileName,DllFuncName,out_path):
    PE_DATA = DATA
    DataLen = ctypes.c_int
    DataAddress = ctypes.c_int
    DOSHeader = IMAGE_DOS_HEADER()
    PeHeader = IMAGE_NT_HEADERS()
    IATAdderss = ctypes.c_int

    CustomSegment = IMAGE_SECTION_HEADER()
    kernel32 = ctypes.windll.LoadLibrary("kernel32.dll")
    #SegmentArry = IMAGE_SECTION_HEADER()
    RtlMoveMemory = ctypes.windll.LoadLibrary("kernel32.dll").RtlMoveMemory
    i = ctypes.c_int
    #DEFINE END


    DataLen = len(PE_DATA)
    DataAddress = kernel32.lstrcpynA(PE_DATA, PE_DATA, 0)
    print('DOSHEADER', type(DOSHeader), type(DataAddress))
    print('PE_DADA', type(PE_DATA))
    print('DataAddress', DataAddress, type(DataAddress))
    RtlMoveMemory(ctypes.addressof(DOSHeader), DataAddress, 64)
    if (DOSHeader.e_magic != IMAGE_DOS_SIGNATURE):
        return False
    else:
        print('DataLen:', str(DataLen), str(DOSHeader.e_lfanew + 248))
        if (DataLen < DOSHeader.e_lfanew + 248):
            return False
    RtlMoveMemory(ctypes.addressof(PeHeader), DataAddress + DOSHeader.e_lfanew, 248)
    # print(PeHeader.Signature)
    if (PeHeader.Signature != IMAGE_NT_SIGNATURE):
        return False
    IATAdderss = PeHeader.OptionalHeader.DataDirectory[1].VirtualAddress
    if (IATAdderss == 0):
        return False
    #IAT = ctypes.create_string_buffer(PeHeader.OptionalHeader.DataDirectory[1].Size - 20)#Just fill with hello
    IAT = (ctypes.c_byte * (PeHeader.OptionalHeader.DataDirectory[1].Size - 20))()
    print("IAT_o",type(IAT),PeHeader.OptionalHeader.DataDirectory[1].Size - 20,sys.getsizeof(IAT))
    #IAT = ctypes.c_byte  (PeHeader.OptionalHeader.DataDirectory[1].Size - 20)

    RtlMoveMemory(ctypes.addressof(IAT),DataAddress+IATAdderss,PeHeader.OptionalHeader.DataDirectory[1].Size - 20)
    print("IAT_n", type(IAT),sys.getsizeof(IAT))
    #print(IAT.raw)


    SegmentArry = (IMAGE_SECTION_HEADER * (PeHeader.FileHeader.NumberOfSections))()

    RtlMoveMemory(ctypes.addressof(SegmentArry),DataAddress + DOSHeader.e_lfanew + 248 , PeHeader.FileHeader.NumberOfSections * 40)

    index = 0
    for i in SegmentArry:
        print(i)
        if(IATAdderss >= SegmentArry[index].VirtualAddress and IATAdderss <= SegmentArry[index].VirtualAddress + SegmentArry[index].Misc):
            SegmentArry[index].Characteristics = 2147483648
            break
        index += 1

    #print(len(SegmentArry))

    CustomSegment.Name = __StringToC_ByteArray(".gdata",True)

    CustomSegment.Misc = PeHeader.OptionalHeader.DataDirectory[1].Size + 20 + 8 + len(DllFileName) + 1 + 2 + len(DllFuncName) + 1
    CustomSegment.VirtualAddress = PeHeader.OptionalHeader.SizeOfImage
    CustomSegment.SizeOfRawData = CustomSegment.Misc
    CustomSegment.PointerToRawData = DataLen
    CustomSegment.Characteristics =  2147483648
    #ReDeFineArry
    SegmentArry_new = (IMAGE_SECTION_HEADER * (PeHeader.FileHeader.NumberOfSections + 1 ))()
    for s in range(len(SegmentArry)):
        SegmentArry_new[s] = SegmentArry[s]
    SegmentArry_new[len(SegmentArry)] = CustomSegment
    #ReDeFineEnd

    PeHeader.FileHeader.NumberOfSections = PeHeader.FileHeader.NumberOfSections + 1
    PeHeader.OptionalHeader.DataDirectory [1].Size =  PeHeader.OptionalHeader.DataDirectory [1].Size + 20
    PeHeader.OptionalHeader.DataDirectory[1].VirtualAddress = CustomSegment.VirtualAddress
    PeHeader.OptionalHeader.SizeOfImage = PeHeader.OptionalHeader.SizeOfImage + CustomSegment.Misc
    #print("D+S:", DataAddress + DOSHeader.e_lfanew,ctypes.addressof(PeHeader))
    RtlMoveMemory( DataAddress + DOSHeader.e_lfanew + 248,ctypes.addressof(SegmentArry_new),PeHeader.FileHeader.NumberOfSections * 40)
    #print("D2+S2:", DataAddress + DOSHeader.e_lfanew, ctypes.addressof(PeHeader))
    RtlMoveMemory(DataAddress + DOSHeader.e_lfanew,ctypes.addressof(PeHeader),248)

    script = '''PE_DATA | IAT | __CreateBlackByteArry(12) | __IntToC_ByteArray(CustomSegment.VirtualAddress + PeHeader.OptionalHeader.DataDirectory[1].Size +8) |
        __IntToC_ByteArray(CustomSegment.VirtualAddress + PeHeader.OptionalHeader.DataDirectory [1].Size) | __CreateBlackByteArry(20) |
        __IntToC_ByteArray(CustomSegment.VirtualAddress + PeHeader.OptionalHeader.DataDirectory[1].Size + 8 + len(DllFileName) +1 ) |
        __CreateBlackByteArry(4) | __StringToC_ByteArray(DllFileName,) | __CreateBlackByteArry(3) | __StringToC_ByteArray(DllFuncName,) | __CreateBlackByteArry(1)
    '''

    out = open(out_path,'wb')
    for i in script.split("|"):
        #print(i,eval("len(%s)"% i))
        eval("out.write(%s)" % i)
    out.close()
    print("%s is OK!"%out_path)
    return True


def LoadIAT(DATA):
    PE_DATA = DATA
    DataLen = ctypes.c_int
    DataAddress = ctypes.c_int
    DOSHeader=IMAGE_DOS_HEADER()
    PeHeader=IMAGE_NT_HEADERS()
    #IATArray=(IMAGE_IMPORT_DESCRIPTOR *10)()
    IATAdderss=ctypes.c_int
    IATNum = ctypes.c_int
    ArrayIndex=ctypes.c_int
    ModlesName=ctypes.c_int
    AdderssTable = ctypes.c_int
    Names = ctypes.c_int(123456)

    IAT = ctypes.c_byte
    kernel32 =  ctypes.windll.LoadLibrary("kernel32.dll")
    RtlMoveMemory = ctypes.windll.LoadLibrary("kernel32.dll").RtlMoveMemory
    ReadProcessMemory = ctypes.windll.LoadLibrary("kernel32.dll").ReadProcessMemory
    #DEFINE END

    DataLen=len(PE_DATA)
    DataAddress = kernel32.lstrcpynA(PE_DATA,PE_DATA,0)
    print('DOSHEADER',type(DOSHeader),type(DataAddress))
    print('PE_DADA',id(PE_DATA))
    print('DataAddress',DataAddress, type(DataAddress))
    RtlMoveMemory(ctypes.addressof(DOSHeader),DataAddress,64)
    if(DOSHeader.e_magic != IMAGE_DOS_SIGNATURE):
        return False
    else:
        print('DataLen:',str(DataLen),str(DOSHeader.e_lfanew + 248))
        if(DataLen < DOSHeader.e_lfanew + 248):
            return False
    RtlMoveMemory(ctypes.addressof(PeHeader),DataAddress+DOSHeader.e_lfanew ,248)
    #print(PeHeader.Signature)
    if(PeHeader.Signature != IMAGE_NT_SIGNATURE):
        return False
    IATAdderss = PeHeader.OptionalHeader.DataDirectory[1].VirtualAddress
    if(IATAdderss ==0):
        return False
    IATNum = PeHeader.OptionalHeader.DataDirectory[1].Size/20
    IATArray = (IMAGE_IMPORT_DESCRIPTOR * IATNum)()
    RtlMoveMemory(ctypes.addressof(IATArray),DataAddress+IATAdderss,IATNum * 20)
    for index in range(IATNum-1):
        ModlesName = DataAddress + IATArray[index].Name
        print("DLL NAME:%s" % ctypes.string_at(ModlesName))
        #print('Mod:',type(ModlesName))
        AdderssTable = DataAddress + IATArray[index].FirstThunk# IAT HOOK IS ON THIS WRITE OUR FUNC ADDRESS.
        #print('AdderssTable', AdderssTable, type(AdderssTable))
        RtlMoveMemory(ctypes.addressof(Names),AdderssTable,4)
        while(Names != 0):

            #print(Names.value,Names )
            if((Names.value & IMAGE_ORDINAL_FLAG32) == 0):#Name or Number
                Names =ctypes.c_int( DataAddress + Names.value + 2)
                try:
                    if (ctypes.string_at(Names.value)== "\x90"):
                        break
                except:
                    break
                print("Func Name:%s"%ctypes.string_at(Names.value))
            else:
                Names = ctypes.c_int(Names.value & 65535)
                print("FUNC NUMBER:%d"% Names.value)
            AdderssTable = AdderssTable + 4
            RtlMoveMemory(ctypes.addressof(Names), AdderssTable, 4)

        #print("Func Name:%s" % buf.read())


def Main():
    file_obj = open("d:\\300.exe",'rb')
    #IATHOOK(file_obj.read(),"abc","abc","d:\\exp.exe")
    LoadIAT(file_obj.read())
    file_obj.close()
Main()
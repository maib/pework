// pework by jz
//
// http://jz.pe.kr
// cmpdebugger@gmail.com
//
// version 0.1
//
// all rights reserved.
// modify & use freely at your own risk, 
// but do not distribute without author's permission.
// 
// pework is released under GPL


#include "pework.h"

static DWORD GetCeiling( DWORD ulValue, DWORD ulAlign );
static DWORD GetFloor( DWORD ulValue, DWORD ulAlign );

#define vmalloc( size )		VirtualAlloc( NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE )
#define vfree( addr )		VirtualFree( addr, 0, MEM_RELEASE )


#define MAX_SECTION_COUNT	100
#define EG( var, label )			do{ if( ( var ) == FALSE ) goto label; }while(0)



pework::pework()
{
	memset( filepath, 0, MAX_PATH );
	memset( &dh, 0, sizeof(dh) );
	memset( &nh, 0, sizeof(nh) );
	shlist = NULL;
	numberOfSections = 0;
	isOpened = FALSE;
}


pework::~pework()
{
	Close();
}


BOOL pework::Open( char *file )
{
	BOOL result = TRUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BYTE buf[0x1000];
	DWORD rw;

	ZeroMemory( buf, 0x1000 );

	hFile = CreateFile( file,
						GENERIC_READ,
						FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						0,
						NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		result = FALSE;
		goto _END;
	}

	// alloc & getinfo



	if( ReadFile( hFile, buf, 0x1000, &rw, NULL ) == FALSE )
	{
		result = FALSE;
		goto _END;
	}

	result = OpenBuffer( buf, rw );


_END:

	if( hFile != INVALID_HANDLE_VALUE )
		CloseHandle( hFile );

	return result;

}


BOOL pework::OpenBuffer( BYTE *buf, DWORD size )
{
	BOOL result = TRUE;

	if( size < sizeof(IMAGE_DOS_HEADER) )
	{
		result = FALSE;
		goto _END;
	}


	memcpy( &dh, buf, sizeof(IMAGE_DOS_HEADER) );

	if( dh.e_magic != 0x5a4d )
	{
		result = FALSE;
		goto _END;
	}

	if( size < dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) )
	{
		result = FALSE;
		goto _END;
	}

	// PE
	memcpy( &nh.Signature, buf + dh.e_lfanew, sizeof(DWORD) );
	// FILE HEADER
	memcpy( &nh.FileHeader, buf + dh.e_lfanew + sizeof(DWORD), sizeof(IMAGE_FILE_HEADER) );

	if( size < dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nh.FileHeader.SizeOfOptionalHeader )
	{
		result = FALSE;
		goto _END;
	}
	//memcpy( &nh.OptionalHeader, buf + dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), nh.FileHeader.SizeOfOptionalHeader );
	memcpy( &nh.OptionalHeader, buf + dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_OPTIONAL_HEADER) );

	if( nh.Signature != 0x4550 )
	{
		result = FALSE;
		goto _END;
	}

	numberOfSections = nh.FileHeader.NumberOfSections;
	if( numberOfSections >= MAX_SECTION_COUNT )
	{
		result = FALSE;
		goto _END;
	}

	shlist = (IMAGE_SECTION_HEADER*)vmalloc( sizeof(IMAGE_SECTION_HEADER) * numberOfSections );
	if( shlist == NULL )
	{
		result = FALSE;
		goto _END;
	}

//	if( nh.FileHeader.SizeOfOptionalHeader > 0xe0 )
//		nh.FileHeader.SizeOfOptionalHeader = 0xe0;

	memcpy( shlist, 
			buf + dh.e_lfanew + sizeof(DWORD) + sizeof(nh.FileHeader) + nh.FileHeader.SizeOfOptionalHeader,
			sizeof(IMAGE_SECTION_HEADER) * nh.FileHeader.NumberOfSections );



	// 특수상황들
	if( nh.OptionalHeader.SectionAlignment == 0x1000 )
		nh.OptionalHeader.FileAlignment = 0x200;

	isOpened = TRUE;

_END:

	return result;

}



BOOL pework::OpenByStructs( IMAGE_DOS_HEADER *dosheader, 
							IMAGE_NT_HEADERS *ntheader,
							IMAGE_SECTION_HEADER *sectionheaders,
							int numberofsectionheaders )
{
	BYTE *buf = NULL;
	int size;

	if( isOpened == TRUE )
	{
		this->Close();
		isOpened = FALSE;
	}

	memcpy( &dh, dosheader, sizeof(IMAGE_DOS_HEADER) );
	memcpy( &nh, ntheader, sizeof(IMAGE_NT_HEADERS) );


	size = sizeof(IMAGE_SECTION_HEADER) * numberofsectionheaders;

	shlist = (IMAGE_SECTION_HEADER*) vmalloc( size );
	if( shlist == NULL )
		return FALSE;

	ZeroMemory( shlist, size );

	memcpy( shlist, sectionheaders, size );

	isOpened = TRUE;


	return TRUE;

}



void pework::Close()
{

	memset( filepath, 0, MAX_PATH );
	memset( &dh, 0, sizeof(dh) );
	memset( &nh, 0, sizeof(nh) );

	if( shlist != NULL )
	{
		vfree( shlist );
		shlist = NULL;
	}
	numberOfSections = 0;

	isOpened = FALSE;

}



BOOL pework::WriteToFile( HANDLE h )
{
	BOOL result = FALSE;
	DWORD rw;

	SetFilePointer( h, 0, NULL, FILE_BEGIN );


	// IMAGE_DOS_HEADER
	EG( WriteFile( h, &dh, sizeof(IMAGE_DOS_HEADER), &rw, NULL ), _end );
	if( rw != sizeof(IMAGE_DOS_HEADER) )
		goto _end;


	EG( SetFilePointer( h, dh.e_lfanew, NULL, FILE_BEGIN ), _end );


	EG( WriteFile( h, &nh, sizeof(IMAGE_NT_HEADERS), &rw, NULL ), _end );
	if( rw != sizeof(IMAGE_NT_HEADERS) )
		goto _end;


	EG( WriteFile( h, shlist, sizeof(IMAGE_SECTION_HEADER) * nh.FileHeader.NumberOfSections, &rw, NULL ), _end );
	if( rw != sizeof(IMAGE_SECTION_HEADER) * nh.FileHeader.NumberOfSections )
		goto _end;


	result = TRUE;

_end:

	return result;
}



IMAGE_DOS_HEADER *pework::GetDH()
{
	if( !isOpened )
		return NULL;
	return &dh;
}


IMAGE_NT_HEADERS *pework::GetNH()
{
	if( !isOpened )
		return NULL;
	return &nh;
}

IMAGE_SECTION_HEADER *pework::GetSH( int index )
{
	if( !isOpened )
		return NULL;
	return &shlist[index];
}

IMAGE_SECTION_HEADER *pework::GetAllSH()
{
	if( !isOpened )
		return NULL;
	return shlist;
}

int pework::GetNumberOfSections()
{
	if( !isOpened )
		return -1;
	return numberOfSections;
}

DWORD pework::GetEPRva()
{
	if( !isOpened )
		return (DWORD)-1;
	return nh.OptionalHeader.AddressOfEntryPoint;
}

DWORD pework::GetEPRaw()
{
	if( !isOpened )
		return (DWORD)-1;
	return Rva2Raw( nh.OptionalHeader.AddressOfEntryPoint );
}

DWORD pework::GetImageBase()
{
	if( !isOpened )
		return (DWORD)-1;
	return nh.OptionalHeader.ImageBase;
}

DWORD pework::Rva2Raw( DWORD rva )
{
	int i;
	DWORD raw;
	DWORD fileAlign, sectionAlign;
	DWORD realSectionStart, realSectionEnd;

	if( !isOpened )
		return (DWORD)-1;

	fileAlign = nh.OptionalHeader.FileAlignment;
	sectionAlign = nh.OptionalHeader.SectionAlignment;


	if( rva < nh.OptionalHeader.SizeOfHeaders )
	{
		return rva;
	}

	for( i = 0; i < numberOfSections; i ++ )
	{
		realSectionStart = GetCeiling( shlist[i].VirtualAddress, sectionAlign );
		realSectionEnd = realSectionStart + GetCeiling( shlist[i].Misc.VirtualSize, sectionAlign );
		if( rva >= realSectionStart && 
			rva < realSectionEnd )
		{
			raw = ( rva - realSectionStart + GetFloor( shlist[i].PointerToRawData, fileAlign ) );
			return raw;
		}
	}

	return -1;
}



DWORD pework::Va2Raw( DWORD va )
{
	return Rva2Raw( va - nh.OptionalHeader.ImageBase );
}



IMAGE_SECTION_HEADER *pework::GetEPSH()
{
	DWORD ep = this->GetEPRva();

	for( int i = 0; i < this->GetNumberOfSections(); i ++ )
	{
		if( ep >= shlist[i].VirtualAddress &&
			ep < GetCeiling( shlist[i].VirtualAddress  + shlist[i].Misc.VirtualSize, nh.OptionalHeader.SectionAlignment ) )
			return &shlist[i];
	}

	return NULL;
}



DWORD GetCeiling( DWORD ulValue, DWORD ulAlign )
{
	DWORD ulLeft;

	if ( ulAlign == 0 )
		ulAlign = 1;

	ulLeft = ulValue % ulAlign;

	if ( ulLeft != 0 )
	{
		return ulValue + ulAlign - ulLeft;
	}
	else
	{
		return ulValue;
	}
}

DWORD GetFloor( DWORD ulValue, DWORD ulAlign )
{
	DWORD ulLeft;

	if ( ulAlign == 0 )
		ulAlign = 1;

	ulLeft = ulValue % ulAlign;

	return ulValue - ulLeft;
}




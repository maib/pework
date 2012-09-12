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


#ifndef _WINDOWS_
#include <windows.h>
#endif


class pework
{
	char filepath[MAX_PATH];

	IMAGE_DOS_HEADER dh;
	IMAGE_NT_HEADERS nh;
	int numberOfSections;
	IMAGE_SECTION_HEADER *shlist;
	BOOL isOpened;

public:

	pework();
	~pework();

	BOOL Open( char *file );
	BOOL OpenBuffer( BYTE *buf, DWORD size );
	BOOL OpenByStructs( IMAGE_DOS_HEADER *dosheader, 
						IMAGE_NT_HEADERS *ntheader,
						IMAGE_SECTION_HEADER *sectionheaders,
						int numberofsectionheaders );
	void Close();
	BOOL WriteToFile( HANDLE h );
	IMAGE_DOS_HEADER *GetDH();
	IMAGE_NT_HEADERS *GetNH();
	int GetNumberOfSections();
	IMAGE_SECTION_HEADER *GetSH( int index );
	IMAGE_SECTION_HEADER *GetAllSH();
	IMAGE_SECTION_HEADER *GetEPSH();
	DWORD GetEPRva();
	DWORD GetEPRaw();
	DWORD GetImageBase();
	DWORD Rva2Raw( DWORD rva );
	DWORD Va2Raw( DWORD va );
	
};


# pe parser class #

example
```
pework pe;
pe.Open( "c:\\windows\\system32\\calc.exe" );
printf( "entry point : 0x%08x\n", pe.GetNH()->OptionalHeader.AddressOfEntryPoint );
for( int i = 0; i < pe.GetNumberOfSections(); i ++ )
{
    printf( "section %d [%s] : %08x ~ %08x\n", 
             i + 1,
             pe.GetSH(i)->Name, 
             pe.GetImageBase() + pe.GetSH(i)->VirtualAddress, 
             pe.GetImageBase() + pe.GetSH(i)->VirtualAddress + pe.GetSH(i)->Misc.VirtualSize );
}

----
section 1 [.text] : 01001000 ~ 010136b0
section 2 [.data] : 01014000 ~ 0101501c
section 3 [.rsrc] : 01016000 ~ 0101e960
```
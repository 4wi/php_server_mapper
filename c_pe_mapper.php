<?php
require_once "c_mem.php";
class c_pe_mapper
{
    private $bin;
    private $mem_mgr;
    private $size_of_image, $base;
    private $sections = array( );
    private $imports = array( );
    private $relocs = array( );
    private $mapped_bin = array( );
    private $entry = 0;

    public function __construct( string $path ) {
        $handle = fopen( $path, "rb" );
        $file_size = filesize( $path );
        $contents = fread( $handle, $file_size );
        $this->bin = unpack( "C*", $contents );
        fclose( $handle );

        $this->mem_mgr = new c_mem( );
    }

    public function initialize( ) : int {
        $dos_nt_offset = $this->mem_mgr->read_dword( $this->bin, 0x3C + 0x1 );
        $nt_sig = $this->mem_mgr->read_dword( $this->bin, $dos_nt_offset + 0x1 );

        if ( $nt_sig != 0x4550 )
            return 1; // invalid nt signature

        $size_of_image = $this->mem_mgr->read_dword( $this->bin, $dos_nt_offset + 0x50 + 0x1 );
        $size_of_header = $this->mem_mgr->read_word( $this->bin, $dos_nt_offset + 0x54 + 0x1 );

        $this->base = $this->mem_mgr->read_dword( $this->bin, $dos_nt_offset + 0x34 + 0x1 );
        $this->size_of_image = $size_of_image;

        $mapped_bin = array_fill( 0, $size_of_image, 0 );
        $mapped_bin = $this->mem_mgr->mem_copy( $this->bin, $mapped_bin, 0, 1, $size_of_header );

        $num_of_sections = $this->mem_mgr->read_word( $mapped_bin, $dos_nt_offset + 0x6 );
        $section_header = array_fill( 0, 0x28 * $num_of_sections, 0 );
        $section_header = $this->mem_mgr->mem_copy( $mapped_bin, $section_header, 0,
            $dos_nt_offset + 0xF8, 0x28 * $num_of_sections );

        $this->entry = $this->mem_mgr->read_dword( $mapped_bin, $dos_nt_offset + 0x28 );

        for ( $i = 0; $i < $num_of_sections; $i++ ) {
            $name = "";
            foreach ( $this->mem_mgr->read_qword( $section_header, $i * 0x28 ) as $char )
                $name .= chr( $char );

            $va = $this->mem_mgr->read_dword( $section_header, $i * 0x28 + 0xC );
            $ptr = $this->mem_mgr->read_dword( $section_header, $i * 0x28 + 0x14 );
            $size = $this->mem_mgr->read_dword( $section_header, $i * 0x28 + 0x10 );

            $this->sections[ $name ] = array(
                "virtual_address" => $va,
                "ptr_to_raw" => $ptr,
                "size" => $size
            );

            if ( $name == ".reloc" ) {
                for ( $j = 0; $j < $size; $j++ )
                    $this->bin[ $ptr + $j + 1 ] = 0;
            }

            $mapped_bin = $this->mem_mgr->mem_copy( $this->bin, $mapped_bin, $va, $ptr + 1, $size );
        }

        $directories = array_fill( 0, 0x8 * 16, 0 );
        $directories = $this->mem_mgr->mem_copy( $mapped_bin, $directories, 0,
            $dos_nt_offset + 0x78, 0x8 * 16 );

        $imp_dir_offset = $this->mem_mgr->read_dword( $directories, 0x8 );

        $imports = array_fill( 0, $this->mem_mgr->read_dword( $directories, 0x8 + 4 ), 0 );
        $imports = $this->mem_mgr->read_mem( $mapped_bin, $imp_dir_offset, count( $imports ) );

        while ( $this->mem_mgr->read_dword( $imports, 0 ) > 0 ) {
            $module_name = $this->mem_mgr->read_string( $mapped_bin,
                $this->mem_mgr->read_dword( $imports, 0xC ) );

            $thunk_offset = 0;
            $orig_thunk = $this->mem_mgr->read_mem( $mapped_bin,
                $this->mem_mgr->read_dword( $imports, 0x0 ), 4 );

            if ( mb_substr( $module_name, 0, 7 ) == "api-ms-" )
                $module_name = "ucrtbase.dll";

            while ( $this->mem_mgr->read_dword( $orig_thunk, 0 ) > 0 ) {
                $thunk_data = $this->mem_mgr->read_dword( $orig_thunk, 0 );
                if ( $thunk_data & 0x80000000 ) {
                    $function = $thunk_data & 0xFFFF;
                } else {
                    $function = $this->mem_mgr->read_string( $mapped_bin,
                        $this->mem_mgr->read_dword( $orig_thunk, 0 ) + 2 );
                }

                $this->imports[ $module_name ][ $function ] = $this->mem_mgr->read_dword( $imports, 0x10 )
                    + $thunk_offset;

                $thunk_offset += 4;
                $orig_thunk = $this->mem_mgr->read_mem( $mapped_bin,
                    $this->mem_mgr->read_dword( $imports, 0x0 ) + $thunk_offset, 4 );
            }

            $imp_dir_offset += 0x14;
            $imports = $this->mem_mgr->read_mem( $mapped_bin, $imp_dir_offset, count( $imports ) );
        }

        $reloc_dir_offset = $this->mem_mgr->read_dword( $directories, 0x8 * 5 );

        $relocs = array_fill( 0, $this->mem_mgr->read_dword( $directories, 0x8 * 5 + 4 ), 0 );
        $relocs = $this->mem_mgr->read_mem( $mapped_bin, $reloc_dir_offset, count( $relocs ) );

        while ( $this->mem_mgr->read_dword( $relocs, 0 ) > 0 ) {
            // CODE VIRTUALIZER AND THEMIDA SUPPORT! NEVER SEEN BEFORE
            if ( $this->mem_mgr->read_dword( $relocs, 0 ) >= $size_of_image )
                break;
            // END OF CODE VIRTUALIZER AND THEMIDA SUPPORT! NEVER SEEN BEFORE

            $num_of_relocs = ( $this->mem_mgr->read_dword( $relocs, 4 ) - 8 ) / 2;
            $block = $this->mem_mgr->read_mem( $mapped_bin, $reloc_dir_offset + 8, $num_of_relocs * 2 );

            for ( $i = 0; $i < $num_of_relocs; $i++ ) {
                $block_offset = $this->mem_mgr->read_word( $block, $i * 2 );
                if ( $block_offset >> 0xC != 3 )
                    continue;

               $this->relocs[ ] = $this->mem_mgr->read_dword( $relocs, 0 ) + ( $block_offset & 0xFFF );
            }

            $reloc_dir_offset += $this->mem_mgr->read_dword( $relocs, 4 );
            $relocs = $this->mem_mgr->read_mem( $mapped_bin, $reloc_dir_offset, count( $relocs ) );
        }

        $this->mapped_bin = $mapped_bin;
        return 0;
    }

    public function map( int $base, array $imports ) : array {
        $mapped_bin = array_fill( 0, $this->size_of_image, 0 );
        foreach ( $this->sections as $section ) {
            $mapped_bin = $this->mem_mgr->mem_copy( $this->mapped_bin, $mapped_bin,
                $section[ "virtual_address" ], $section[ "virtual_address" ], $section[ "size" ] );
        }

        foreach ( $this->relocs as $reloc ) {
            $mapped_bin = $this->mem_mgr->set_dword( $mapped_bin, $reloc,
                $this->mem_mgr->read_dword( $mapped_bin, $reloc ) + $base - $this->base );
        }

        foreach ( $this->imports as $module => $functions ) {
            if ( empty( $imports[ $module ] ) || !is_array( $imports[ $module ] ) )
                return array( );

            foreach ( $functions as $function => $rva ) {
                if ( empty( $imports[ $module ][ $function ] ) )
                    return array( );

                $mapped_bin = $this->mem_mgr->set_dword( $mapped_bin, $rva, $imports[ $module ][ $function ] );
            }
        }

        return $mapped_bin;
    }

    public function get_loader_data( ) : array {
        $imports = array( );
        foreach ( $this->imports as $module => $functions ) {
            foreach ( $functions as $function => $rva )
                $imports[ $module ][ ] = $function;
        }

        return (
            array(
                "imports" => $imports,
                "size" => $this->size_of_image,
                "entry" => $this->entry
            )
        );
    }
}
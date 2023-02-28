<?php
class c_mem {
    public function read_mem( array $source, int $offset, int $size ) : array {
        $result = array( );
        for ( $i = $offset; $i < $offset + $size; $i++ )
            $result[ ] = $source[ $i ];

        return $result;
    }

    public function mem_copy( array $source, array $dest, int $dest_offset, int $offset, int $size ) : array {
        $mem = $this->read_mem( $source, $offset, $size );
        for ( $i = $dest_offset; $i < $dest_offset + $size; $i++ )
            $dest[ $i ] = $mem[ $i - $dest_offset ];

        return $dest;
    }

    public function set_dword( array $dest, int $offset, int $delta ) : array {
        $replacement = unpack( "C*", pack( "L", $delta ) );
        for ( $i = $offset; $i < $offset + 4; $i++ )
            $dest[ $i ] = $replacement[ $i - $offset + 1 ];

        return $dest;
    }

    public function read_dword( array $source, int $offset ) : int {
        $arr = $this->read_mem($source, $offset, 4);
        return (($arr[3] & 0xFF) << 24) | (($arr[2] & 0xFF) << 16) | (($arr[1] & 0xFF) << 8) | ($arr[0] & 0xFF);
    }

    public function read_qword( array $source, int $offset ) : array {
        return $this->read_mem($source, $offset, 8);
    }

    public function read_word( array $source, int $offset ) : int {
        $arr = $this->read_mem($source, $offset, 2);
        return (($arr[1] & 0xFF) << 8) | ($arr[0] & 0xFF);
    }

    public function read_string( array $source, int $offset ) : string {
        $result = "";
        while ( $source[ $offset ] != 0 )
            $result .= chr( $source[ $offset++ ] );

        return $result;
    }
}
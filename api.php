<?php
require_once "c_pe_mapper.php";

$mapper = new c_pe_mapper( "Project1.dll" );
$status = $mapper->initialize( );

if ( $status != 0 ) {
    echo json_encode( array( "status" => $status ), JSON_UNESCAPED_SLASHES );
    exit( );
}

if ( isset( $_GET[ "data" ] ) ) {
    echo json_encode( $mapper->get_loader_data( ), JSON_UNESCAPED_SLASHES );
} elseif ( isset( $_GET[ "image" ] ) ) {
    if ( !isset( $_GET[ "base" ] ) || !isset( $_GET[ "imports" ] ) ) {
        echo json_encode( array( "success" => false ), JSON_UNESCAPED_SLASHES );
        exit( );
    }

    $mapped_bin = $mapper->map( intval( $_GET[ "base" ] ), json_decode( $_GET[ "imports" ], 1 ) );
    if ( count( $mapped_bin ) < 0x1000 ) {
        echo json_encode( array( "success" => false ), JSON_UNESCAPED_SLASHES );
        exit( );
    }

    echo json_encode( $mapped_bin, JSON_UNESCAPED_SLASHES );
}
<?php
require_once "c_pe_mapper.php";

$mapper = new c_pe_mapper( "Project1.dll" );
$status = $mapper->initialize( );
if ( $status != 0 )
    echo "failed cause of " . $status;

//echo "init passed successfully!";

$mapper_data = json_decode( $mapper->get_loader_data( ), 1 );
$imports = array( );
foreach ( $mapper_data[ "imports" ] as $import => $functions ) {
    foreach ( $functions as $function )
        $imports[ $import ][ $function ] = 0x14881488;
}

print_r( $mapper->map( 0x30000000, $imports ) );
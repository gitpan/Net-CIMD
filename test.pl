#!/bin/env perl
#
# Copyright (c) 2013 Badr Zarhri <badr.zarhri@gmail.com>, <badr.zarhri.ext@nsn.com>, All rights reserved.
# See README for license. NO WARRANTY.
#
# $Id: test.pl,v 0.1 2013/06/23 19:04:59 zarhri Exp $
#
# Test Net::CIMD in Client role
#
# Usage: ./test.pl

use Net::CIMD;
use v5.8;
use Data::Dumper;
use Carp;

my $ip_address='127.0.0.1';
my $port='9971';
my $login='testCIMD';
my $password='Ba123!';

local $Carp::CarpLevel = 1;

my $cimd=Net::CIMD->login(
                        host    =>      $ip_address,
                        port    =>      $port,
                        user_identity   =>      $login,
                        password        =>      $password,
			local_ip	=>	$ip_address
                        ) or croak "Cannot connect to $ip_address $!\n";
$cimd->submit(
		destination_address	=>	'00212661123456',
		originating_address	=>	'2727',
		data_coding_scheme	=>	0,
		user_data	=>	'Salam cava ?',
		first_delivery_time_relative	=>	1,
		status_report_request	=>	12,
		priority	=>	1
		);


my $resp=$cimd->read_sync();

print Dumper($resp)."\n";


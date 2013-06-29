# Net::CIMD.pm  -  CIMD over TCP, pure perl implementation
# Copyright (c) 2013 Badr Zarhri <badr.zarhri@gmail.com>, <badr.zarhri.ext@nsn.com>, All rights reserved.
# This code may be distributed under same terms as perl. NO WARRANTY.
# The implementation of this module is based on CIMD interface specification available in the internet.
# I should mention that Net::SMPP of Sampo Kellomaki <sampo@iki.fi> was of great help in implementing this protocol.
# Writing this module in perl makes it independant of other packages (it requires only a working perl installation).
# This module was tested in perl 5.8.8 (redhat EL 5), and 5.16.3 (centos 6.3).
# Please feel free to contact me if you've any remarks or ideas to improve this work.
# 23-June-2013, Created the module -- Badr
# 27-June-2013, fixed decode RE to handle nack --Badr

package Net::CIMD;

use 5.008008;
use strict;
use warnings;
use Carp;
use IO::Socket;
use Data::Dumper;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::CIMD ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01_02';


my $trace = 0;
my %inv_op;
my %inv_par;
use constant Defaults => {
	host	=>	"127.0.0.1",
	port => 9971,
	local_ip => "127.0.0.1",
	timeout => 30
};
# CIMD interface specification 3.5 operation codes
use constant operation => {
	login	=>	"01",
	login_resp	=>	"51",
	logout	=>	"02",
	logout_resp	=>	"52",
	submit	=>	"03",
	submit_resp	=>	"53",
	submit_status_report	=>	"13",
	submit_status_report_resp	=>	"63",
	enquire_message_status	=>	"04",
	enquire_message_status_resp	=>	"54",
	delivery_request	=>	"05",
	delivery_request_resp	=>	"55",
	cancel	=>	"06",
	cancel_resp	=>	"56",
	deliver_message	=>	"20",
	deliver_message_resp	=>	"70",
	deliver_status_report	=>	"23",
	deliver_status_report_resp	=>	"73",
	set_parameters	=>	"08",
	set_parameters_resp	=>	"58",
	get_parameters	=>	"09",
	get_parameters_resp	=>	"59",
	alive	=>	"40",
	alive_resp	=>	"90",
	general_error_resp	=>	"98",
	nack	=>	"99"
};
# CIMD specification 7.2 parameters.
use constant parameter => {
	user_identity	=>	"010",
	password	=>	"011",
	subaddr	=>	"012",
	window_size	=>	"019",
	destination_address	=>	"021",
	originating_address	=>	"023",
	originating_IMSI	=>	"026",
	alphanumeric_ariginating_address	=>	"027",
	originated_visited_MSC_address	=>	"028",
	data_coding_scheme	=>	"030",
	user_data_header	=>	"032",
	user_data	=>	"033",
	user_data_binary	=>	"034",
	more_messages_to_send	=>	"044",
	validity_Period_Relative	=>	"050",
	validity_Period_Absolute	=>	"051",
	protocol_identifier	=>	"052",
	first_delivery_time_relative	=>	"053",
	first_delivery_time_absolute	=>	"054",
	reply_path	=>	"055",
	status_report_request	=>	"056",
	cancel_enabled	=>	"058",
	cancel_mode	=>	"059",
	service_centre_time_stamp	=>	"060",
	status_code	=>	"061",
	status_error_code	=>	"062",
	discharge_time	=>	"063",
	tariff_class	=>	"064",
	service_description	=>	"065",
	message_count	=>	"066",
	priority	=>	"067",
	delivery_request_mode	=>	"068",
	service_center_address	=>	"069",
	IP_address	=>	"071",
	get_parameter	=>	"500",
	SMS_center_time	=>	"501",
	error_code	=>	"900",
	error_text	=>	"901"
};

BEGIN {
	foreach( keys %{&operation})
	{
		$inv_op{operation->{$_}}=$_;
	}
	foreach( keys %{&parameter} )
	{
		$inv_par{parameter->{$_}}=$_;
	}
}
sub new_connect {
    my %arg = @_;
	my %parms=(
         PeerAddr  => exists $arg{host} ? $arg{host} : Defaults->{host},
         PeerPort  => exists $arg{port} ? $arg{port} : Defaults->{port},
         LocalAddr => exists $arg{local_ip} ? $arg{local_ip} : Defaults->{local_ip},
         Proto     => 'tcp',
         Timeout   => exists $arg{timeout} ? $arg{timeout} : Defaults->{timeout} );
    my $s = IO::Socket::INET->new(%parms)  # pass any extra args to constructor
        or croak "Can't connect $! $@\n";
	return undef unless defined $s;
	$s->autoflush(1);
	return $s;
}

# buffer here is for future use.
sub receive_packet {
        my $me=shift;
        my $temp;
        while ($me->{tunnel}->sysread($temp, 1)) {
                $me->{buffer} .= $temp;
		last if($me->{buffer} =~ /\x09(?:..)?\x03$/);
        }
        my $result=$me->{buffer};
        $me->{buffer}="";
        return $result;
}

sub send_packet {
    my $me = shift;
    my $data = shift;
    $me->{seq}=sprintf("%03d", (($me->{seq}+2)%1000));
    carp "sending packet :\n".hexdump($data,"\t") if $trace;
    $me->{tunnel}->syswrite($data) or return undef;
	return 'Ok';
}

sub login {
    my $type = shift;
	$type=ref($type) || $type;
    my $tunnel = new_connect(@_);
    return undef if !defined $tunnel;
	my $me= bless {
		seq	=>	"001",
		buffer	=>	"",
		checksum	=>	0,
		tunnel	=>	$tunnel
		}, $type;
	my %args=@_;
    $me->send_packet($me->encode_packet("login", 'user_identity',$args{user_identity},'password',$args{password}));
	my $resp=$me->receive_packet();
	print "received\n".Dumper($resp) if $trace;
    return $me;
}

sub AUTOLOAD {
    my $me = shift;
	my $operation=our $AUTOLOAD;
	$operation =~ s/^.*::([^:]+)$/$1/;
	return undef unless defined (operation->{$operation});
	$me->send_packet($me->encode_packet($operation,@_));
	return "Ok";
}

sub encode_packet {
	my $me=shift;
	my $op=shift;
	my %args=@_;
        my $res="\x02".
	operation->{$op}.":".(defined $args{seq}?$args{seq}:$me->{seq})."\t";
	foreach (sort { parameter->{$a} <=> parameter->{$b} } keys %args)
        {
                $res.=parameter->{$_}.":".$args{$_}."\t" if(defined parameter->{$_});
        }
        return $res.&checksum($res)."\x03";
	#return $res."\x03";
}

sub decode_packet {
	my $me=shift;
	my $data=shift;
	return undef unless($data =~ /^\x02([^:]+):([^\x09]+)\x09(.*\x09)?(..)?\x03/);
	my ($op, $seq)=($1, $2);
	$data=$3;
	my $checksum=$4;
	my %parms;
	$data =~ s/([^:]+):([^\x09]+)\x09/$parms{$inv_par{$1}}=$2/eg;
	return bless {"operation", $inv_op{$op}, "sequence", $seq, %parms}, 'Net::CIMD::PDU';
}

sub checksum {
	my $hash = 0;
	foreach (split //, shift) {
		$hash += ord($_);
		$hash &= 0xFF;
	}
	return sprintf("%02x",$hash);
}
sub read_sync()
{
	my $me=shift;
	my $req=$me->decode_packet($me->receive_packet());
	print "received :\n".Dumper($req);
	$me->send_packet($me->encode_packet($req->{"operation"}."_resp",'seq', $req->{"sequence"})) if defined (operation->{$req->{"operation"}."_resp"});
	return $req;
}
sub DESTROY
{
	my $me=shift;
	$me->logout();
}
package Net::CIMD::PDU;
sub new
{
	my $class=shift;
	return bless {@_}, $class;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::CIMD - pure Perl implementation of CIMD2 over TCP

=head1 SYNOPSIS

  use Net::CIMD;
  my $me=Net::CIMD->login(
                        host    =>      $ip_address,
                        port    =>      $port,
                        user_identity   =>      $login,
                        password        =>      $password,
                        local_ip        =>      $ip_address
                        ) or croak "Cannot connect to $ip_address $!\n";


=head1 DESCRIPTION

Computer Interface for Message Distribution protocol, which is frequently used to
pass short messages between mobile operators implementing short message
service (SMS).

Operations, and parameters names are the same as in cimd specification document.

$me->read_sync() doesn't implement all response messages, but it was tested, and it answers at least to deliver_status_report operation.

This module lack also tests. Tests are ongoing, but you can help by reporting any observed bugs.

Except login method, all other methods work in asychronous mode. Which means it's to the user to wait for the answer for each sent packet.
This approach makes it easier to use speed related mechanisms like windowing.

This module in intended to be used as client or server, but current version supports only client mode.

=head2 CONSTRUCTORS

=item login()

Create a new CIMD client object and open conncetion to SMSC host

	my $cimd=Net::CIMD->login(
                        host    =>      $ip_address,	# defaults to 127.0.0.1
                        port    =>      $port,	# defaults to 9971
                        user_identity   =>      $login
                        password        =>      $password,
                        local_ip        =>      $ip_address,	# defaults to 127.0.01: this parameter is very important when we've many network interfaces.
                        subaddr	=>	$subaddr,
			window_size	=>	$size,
			IP_address	=>	$ip_address	# This is a new parameter not available in SC8.0.
                        ) or croak "Cannot connect to $ip_address $!\n";


It first establish a connexion with the server, and then send the credentials.

=head1 METHODS
Although current version supports only client mode, all CIMD operations are already implemented

=over

=item methods:

=over

	login()
	logout()
	submit()
	enquire_message_status()
	delivery_request()
	cancel()
	set_parameters()
	get_parameters()
	submit_status_report()
	deliver_message()
	deliver_status_report()
	alive()
	login_resp()()
	logout_resp()
	submit_resp()
	enquire_message_status_resp()
	delivery_request_resp()
	cancel_resp()
	set_parameters_resp()
	get_parameters_resp()
	submit_status_report_resp()
	deliver_message_resp()
	deliver_status_report_resp()
	alive_resp()
	general_error_resp()
	nack()

=back

=item parameters:

Previous methods can be used with the folowing parameter names:

=over

	user_identity
	password
	subaddr
	window_size
	destination_address
	originating_address
	originating_IMSI
	alphanumeric_ariginating_address
	originated_visited_MSC_address
	data_coding_scheme
	user_data_header
	user_data
	user_data_binary
	more_messages_to_send
	validity_Period_Relative
	validity_Period_Absolute
	protocol_identifier
	first_delivery_time_relative
	first_delivery_time_absolute
	reply_path
	status_report_request
	cancel_enabled
	cancel_mode
	service_centre_time_stamp
	status_code
	status_error_code
	discharge_time
	tariff_class
	service_description
	message_count
	priority
	delivery_request_mode
	service_center_address
	get_parameter
	SMS_center_time
	error_code
	error_text

=back

As an example, submit message can be wrote like this:

=over

	my $cimd=Net::CIMD->login(
                        host    =>      $ip_address,
                        port    =>      $port,
                        user_identity   =>      $login,
                        password        =>      $password,
                        local_ip        =>      $ip_address
                        ) or croak "Cannot connect to $ip_address $!\n";
	$cimd->submit(
                destination_address     =>      '00212661093659',
                originating_address     =>      '2727',
                data_coding_scheme      =>      0,
                user_data       =>      'Salam cava ?',
                first_delivery_time_relative    =>      1,
                status_report_request   =>      12,
                priority        =>      1
                );

=back

Current version assumes that all parameters are optional, unlike in the specification. This is mainly because of the lack of time, and will be fixed in next version.
Strong parameters control will be added in future versions.

=head1 Receiving PDUs

For reception, this module has methods that send ACK before returning the packet, and other that don't.

=over

=item receive_packet()

This method returns raw packet without sending ACK.

	my $raw_resp=$cimd->receive_packet();

=item read_sync()

This method receives a raw packet from network connexion, decodes it into Net::CIMD::PDU, send the ACK to the remote entity, and then return the decoded PDU.

	my $pdu=$cimd->read_sync();

=head1 OTHER METHODS

Some other useful methods that doesn't require a connexion to an SMSC are also available.

=over

=item decode_packet()

This method is used to decode a raw packet.
It was separated from reading from the stream, so it can be used for other sources of data (for example NetPacket::TCP).

	my $pdu=$cimd->decode_packet($var);
or
	my $pdu=Net::CIMD->decode_packet($var);

=head1 EXAMPLES

Typical client:

=over

	#!/bin/env perl
	
	use Net::CIMD;
	use v5.8;
	use Data::Dumper;
	use Carp;
	
	my $ip_address='127.0.0.1';
	my $port='9971';
	my $login='login';
	my $password='secret';
	
	local $Carp::CarpLevel = 1;
	
	my $cimd=Net::CIMD->login(
		host    =>      $ip_address,
		port    =>      $port,
		user_identity   =>      $login,
		password        =>      $password,
		local_ip        =>      $ip_address
		) or croak "Cannot connect to $ip_address $!\n";
	$cimd->submit(
		destination_address     =>      '00212661093659',
		originating_address     =>      '2727',
		data_coding_scheme      =>      0,
		user_data       =>      'Salam cava ?',
		first_delivery_time_relative    =>      1,
		status_report_request   =>      12,
		priority        =>      1
		);
	
	
	my $resp=$cimd->read_sync();
	
	print Dumper($resp)."\n";

=head1 Limitations

Current version supports only client mode.

CIMD Specific abreviations should be added with encoding methods.

Connexion check is not performed. (when connexion is closed for some reason, the module still use the session).

Text encoding methode should be added.

No restrictions are applied to parameters.

NET::CIMD COMES WITH ABSOLUTELY NO WARRANTY.

=head1 AUTHOR

Badr Zarhri <badr.zarhri@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Badr Zarhri <badr.zarhri@gmail.com>

Net::CIMD is copyright (c) 2013 by Badr Zarhri, All rights reserved.
You may use and distribute Net::CIMD under same terms as perl itself.


=cut

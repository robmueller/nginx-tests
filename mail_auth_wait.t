#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx mail module for WAIT response.

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::IMAP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap http rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    proxy_pass_error_message  on;
    proxy_timeout  15s;
    auth_http  http://127.0.0.1:8080/mail/auth;

    server {
        listen     127.0.0.1:8143;
        protocol   imap;
        imap_auth  plain cram-md5 external;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $upstream_http_count $reply {
	# There won't be a 1, the waitforsocket(...) will get that

	# Each wait is 1 second, so wait 4 times, which should get us
	#  to after the sleep(3), but then after another sleep(2) we
	#  should have completed with a success
	2 WAIT;
	3 WAIT;
	4 WAIT;
	5 WAIT;
	6 OK;
	default ERROR;
    }

    log_format test "reply=$reply";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

	access_log %%TESTDIR%%/auth.log test;

        location = /mail/auth {
            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port %%PORT_8144%%;
            add_header Auth-Pass "";
            add_header Auth-Wait 1;
	    proxy_pass http://127.0.0.1:8083;
	}
    }
}

EOF

$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);
$t->run_daemon(\&http_daemon, port(8083));
$t->run()->plan(4);

$t->waitforsocket('127.0.0.1:' . port(8144));
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

# WAIT response

my $s = Test::Nginx::IMAP->new();
$s->read();
$s->send('a01 LOGIN test@example.com wait');
note("sent LOGIN, sleeping");

sleep(3);

my $f = $t->read_file('auth.log');
my @waits = $f =~ /^reply=WAIT/mg;
ok(@waits >= 2, "found multiple WAIT responses in log");

my @ready = $s->can_read(0.1);
is(scalar @ready, 0, "nothing to read while waiting");

sleep(2);

@ready = $s->can_read(0);
is(scalar @ready, 1, "ready for reading");

$s->ok('login success after waiting');

###############################################################################

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

        my $count = 0;
	while (my $client = $server->accept()) {
		$count++;
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		next if $headers eq '';

		Test::Nginx::log_core('||', "$port: response, 204");
		print $client <<EOF;
HTTP/1.1 204 No content
Count: $count
Connection: close

EOF

	} continue {
		close $client;
	}
}

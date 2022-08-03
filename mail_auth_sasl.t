#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx mail imap module.

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
use Test::Nginx::SMTP;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

local $SIG{PIPE} = 'IGNORE';

my $t = Test::Nginx->new()->has(qw/mail imap smtp http rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    proxy_pass_error_message  on;
    proxy_timeout  15s;
    timeout 2s;
    auth_http  http://127.0.0.1:8080/mail/auth;

    server {
        listen     127.0.0.1:8143;
        protocol   imap;
        imap_auth  plain cram-md5 external oauthbearer;
    }
    server {
        listen     127.0.0.1:8025;
        protocol   smtp;
        smtp_auth  plain external oauthbearer;
    }
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $http_auth_protocol $proxy_port {
	imap %%PORT_8144%%;
	smtp %%PORT_8026%%;
    }

    map $http_auth_pass $reply {
	~secretok OK;
	default auth-failed;
    }
    map $http_auth_pass $passw {
	~secretok secret;
	default "";
    }
    map $http_auth_pass $sasl {
	~saslfail "eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=";
	default "";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

	error_log %%TESTDIR%%/error.log info;

        location = /mail/auth {
            add_header Auth-Status $reply;
            add_header Auth-Server 127.0.0.1;
            add_header Auth-Port $proxy_port;
            add_header Auth-Pass $passw;
            add_header Auth-Wait 1;
	    add_header Auth-Error-Sasl $sasl;
            return 204;
        }
    }
}

EOF

$t->run_daemon(\&Test::Nginx::IMAP::imap_test_daemon);
$t->run_daemon(\&Test::Nginx::SMTP::smtp_test_daemon);
$t->run()->plan(31);

$t->waitforsocket('127.0.0.1:' . port(8144));
$t->waitforsocket('127.0.0.1:' . port(8026));

###############################################################################

# auth oauthbearer
# See https://datatracker.ietf.org/doc/html/rfc7628 for some examples

# SMTP
{

# success, without IR

my $s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer secretok\001\001", ''));
$s->authok('oauthbearer success');

# success, with IR

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER');
$s->check(qr/^334 /, 'auth oauthbearer challenge');
$s->send(encode_base64("n,user=test\@example.com,\001auth=Bearer secretok\001\001", ''));
$s->authok('oauthbearer success');

# fail, sasl failure method, end via sasl 'AQ==' response

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^334 /, 'auth oauthbearer with bad token');
$s->send('AQ==');
$s->check(qr/^535 /, 'got smtp auth failure response after sasl end line');

# fail, sasl failure method, end via empty line

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^334 /, 'auth oauthbearer with bad token');
$s->send('');
$s->check(qr/^535 /, 'got smtp auth failure response after sasl end line');

# fail, sasl failure method, invalid client response causes dropped connection

$s = Test::Nginx::SMTP->new();
$s->read();
$s->send('EHLO example.com');
$s->read();
$s->send('AUTH OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^334 /, 'auth oauthbearer with bad token');
$s->send('foo');
ok($s->eof(), "got disconnect after invalid client line");

}

# IMAP
{

# success, with IR

my $s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer secretok\001\001", ''));
$s->ok('auth bearer success in IR');

# success, without IR

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER');
$s->check(qr/\+ /, 'auth bearer challenge');
$s->send(encode_base64("n,user=test\@example.com,\001auth=Bearer secretok\001\001", ''));
$s->ok('auth bearer success');

# fail, standard non-sasl failure method

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer bad\001\001", ''));
$s->check(qr/^1 NO auth-failed/, 'imap auth failure response');

sleep(3);

my @ready = $s->can_read(0);
is(scalar @ready, 1, "ready for reading");
ok($s->eof(), "session closed");

# fail, sasl failure method, end via empty line

$s = Test::Nginx::IMAP->new();
$s->read();
my $start = time;
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^\+ eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=/, 'got imap sasl failure response');
my $wait_time = time - $start;
ok($wait_time >= 1, 'had to wait at least 1 second to get error line');
$s->send('');
$s->check(qr/^1 NO auth-failed/, 'got imap auth failure response after empty client line');

# fail, sasl failure method, dropped connection
# (closed connection makes ngx_mail_send destroy pool, make
# sure timeout sleep handler doesn't try and use it)

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
sleep(1);
$s->send('');
$s = undef;

sleep(2);

# fail, sasl failure method, end via sasl 'AQ==' response

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^\+ eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=/, 'got imap sasl failure response');
$s->send('AQ==');
$s->check(qr/^1 NO auth-failed/, 'got imap auth failure response after sasl end line');

# fail, sasl failure method, invalid client response causes dropped connection

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^\+ eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=/, 'got imap sasl failure response');
$s->send('foo');
ok($s->eof(), "got disconnect after invalid client line");

# fail, sasl failure method, but Auth-Status: OK is disconnect with internal error

$s = Test::Nginx::IMAP->new();
$s->read();
$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer secretok_saslfail\001\001", ''));
$s->check(qr/^\* BAD internal server error/, 'got internal error response');
ok($s->eof(), "sasl vs error mismatch causes disconnect");

my $e = $t->read_file('error.log');
like($e, qr/returned SASL error to auth success/, "error log documents mismatch error");

# fail, sasl failure method, multiple attempts, then success

$s = Test::Nginx::IMAP->new();
$s->read();

$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^\+ eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=/, 'got imap sasl failure response');
$s->send('');
$s->check(qr/^1 NO auth-failed/, 'got imap auth failure response after empty client line');

$s->send('1 AUTHENTICATE OAUTHBEARER ' . encode_base64("n,user=test\@example.com,\001auth=Bearer saslfail\001\001", ''));
$s->check(qr/^\+ eyJzY2hlbWVzIjoiQmVhcmVyIiwic3RhdHVzIjoiNDAwIn0=/, 'got imap sasl failure response');
$s->send('');
$s->check(qr/^1 NO auth-failed/, 'got imap auth failure response after empty client line');

$s->send('1 AUTHENTICATE OAUTHBEARER');
$s->check(qr/\+ /, 'auth bearer challenge');
$s->send(encode_base64("n,user=test\@example.com,\001auth=Bearer secretok\001\001", ''));
$s->ok('auth bearer success');

}

###############################################################################

package Apache::Authn::GoogleApps;
=head1 NAME

Apache::Authn::GoogleApps - Apache Auth module by Google Apps Account

=head1 SYNOPIS

このファイルをコピー
 /usr/lib/perl5/Apache/Authn/GoogleApps.pm

httpd.conf に

  PerlLoadModule Apache::Authn::GoogleApps
  <Location /svn>
     AuthType Basic
     AuthName GoogleAccount
     Require valid-user

     # ユーザ名に自動で補完するドメイン。
     GoogleAppsDomain example.com
     # 自動で補完するドメインをくっつけるタイミング。Always 常に None 付けない
     # Auto ユーザ名に @ が入っていなければくっつける（hoge と入れたら hoge@example.com にして認証）
     GoogleAppsDomainAppend Always
     # 認証に成功したらその結果をサーバにキャッシュしている時間（秒数）
     # キャッシュするけどスレッドごとに別っぽい（ARP::Pool）
     GoogleAppsCacheCredsMax 3600

     # ハンドラを使う宣言
     PerlAuthenHandler Apache::Authn::GoogleApps::handler
  </Location>

  and reload your apache

=head1 Git URL
  https://github.com/nazoking/perl-apache-authn-googleapps

=head1 AUTHOR

  nazoking "< nazoking@gmail.com >"

=cut

use strict;
use warnings FATAL => 'all', NONFATAL => 'redefine';

use LWP::UserAgent;
use Apache2::Module;
use Apache2::Access;
use Apache2::ServerRec qw();
use Apache2::RequestRec qw();
use Apache2::RequestUtil qw();
use Apache2::Const qw(:common :override :cmd_how);
use APR::Pool ();
use APR::Table ();


my @directives = (
  {
    name => 'GoogleAppsDomain',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'set your google apps domain ex "example.com"',
  },
  {
    name => 'GoogleAppsDomainAppend',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'value select None|Always|Auto',
  },
  {
    name => 'GoogleAppsCacheCredsMax',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'cache time seconds. ex 3600',
  }
);
Apache2::Module::add(__PACKAGE__, \@directives);

sub GoogleAppsDomain{ set_val("GoogleAppsDomain", @_); }
sub GoogleAppsDomainAppend{ set_val("GoogleAppsDomainAppend", @_); }
sub GoogleAppsCacheCredsMax {
  my ($self, $parms, $arg) = @_;
  if ($arg) {
    $self->{GoogleAppsCachePool} = APR::Pool->new;
    $self->{GoogleAppsCacheCreds} = APR::Table::make($self->{GoogleAppsCachePool}, $arg);
    $self->{GoogleAppsCacheCredsMax} = $arg;
  }
}

sub set_val {
  my ($key, $self, $parms, $arg) = @_;
  $self->{$key} = $arg;
}

sub gapp_login{
  my $usr = shift;
  my $pass = shift;
  my $r = shift;
  my $lwp_object = LWP::UserAgent->new;
  my $url = 'https://www.google.com/accounts/ClientLogin';

  my $response = $lwp_object->post( $url, [
    'accountType' => 'HOSTED',
    'Email' => $usr, 'Passwd' => $pass,
    'service' => 'apps'
  ] );
  return $response->is_success;
}

sub cache_login_check{
  my ( $usr , $pass, $cfg, $r ) = @_;
  return 0 unless $cfg->{GoogleAppsCacheCreds};
  my $c = $cfg->{GoogleAppsCacheCreds}->get($usr);
  return 0 unless $c;
  my ($ctime,$cpass) = split(':',$c,2);
  cache_reflesh( $cfg, $r ) if $ctime < time();
  return $cpass eq $pass;
}

sub cache_reflesh{
  my $cfg = shift;
  my $r = shift;
  foreach my $key ( keys %{$cfg->{GoogleAppsCacheCreds}} ){
    my ( $ct, $cp ) = split(':',$cfg->{GoogleAppsCacheCreds}->get($key),2);
    if( $ct < time() ){
      $cfg->{GoogleAppsCacheCreds}->unset( $key );
    }
  }
}

sub cache_login_push{
  my ( $usr , $pass, $cfg, $r ) = @_;
  return 0 unless $cfg->{GoogleAppsCacheCreds};
  cache_reflesh( $cfg, $r );
  $cfg->{GoogleAppsCacheCreds}->set( $usr, ''.(time()+$cfg->{GoogleAppsCacheCredsMax}).':'.$pass );
  return 1;
}

sub handler {
  my $r = shift;
  my ( $st,$pw ) = $r->get_basic_auth_pw();
  my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);
  my $usr = $r->user;

  return $st unless $st == Apache2::Const::OK;
  $usr .= '@'.$cfg->{GoogleAppsDomain} if ( $cfg->{GoogleAppsDomainAppend} eq 'Auto' && $usr !~ /@/ ) || $cfg->{GoogleAppsDomainAppend} ne 'None'; 

  if( defined $usr && defined $pw ){
    if( cache_login_check( $usr, $pw, $cfg, $r ) ){
      return Apache2::Const::OK;
    }elsif( gapp_login( $usr, $pw, $r ) ){
      cache_login_push( $usr, $pw, $cfg, $r );
      return Apache2::Const::OK;
    }
  }
  $r->note_auth_failure();
  return AUTH_REQUIRED;
}

1;

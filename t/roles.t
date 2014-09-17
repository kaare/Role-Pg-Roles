package Test;

use Moose;
use Test::More;

with 'Role::Pg::Roles';

has 'dbh' => (
	is => 'ro',
	isa => 'DBI::db',
);

package Test::Role::Pg::Roles;

use base qw(Test::Class);
use Test::More;

sub db_name {'__rpr:test__'};

sub startup : Test(startup => 1) {
	my $self = shift;
	my $command = 'createdb -e '.db_name;
	qx{$command} || return $self->{skip} = 1;

	ok($self->{dbh} = DBI->connect('dbi:Pg:dbname='.db_name), 'Connect to test database') or return;
};

sub cleanup : Test(shutdown) {
	my $self = shift;
	return if $self->{skip};

	$self->{dbh}->disconnect;
	my $command = 'dropdb '.db_name;
	qx{$command};
};

sub _test : Test(17) {
	my $self = shift;
	return if $self->{skip};

	ok(my $test = Test->new(dbh => $self->{dbh}), 'New Test');
	isa_ok($test,'Test','Test class');
	ok($test->create(role => 'a', password => 'secure!'),'Create a');
	is($test->check_user(user => 'a', password => 'insecure!'), 0, 'Check w/wrong password');
	is($test->check_user(user => 'a', password => 'secure!'), 1, 'Check w/correct password');
	ok($test->create(role => 'b'),'Create b');
	ok($test->create(role => 'c'),'Create c');
	ok($test->add(group => 'b', member => 'a'),'Add a to b');
	is_deeply($test->roles(user => 'a'), [qw/a b/ ], 'A is member of b (and a)');
	ok($test->add(group => 'c', member => 'b'),'Add b to c');
	is_deeply($test->roles(user => 'a'), [qw/a b c/ ], 'A is member of c and b (and a)');
	ok($test->member_of(user => 'a', group => 'c'), 'a is member of c');
	ok($test->drop(role => 'c'),'Drop c (Can remove a role w/o removing all members)');
	is_deeply($test->roles(user => 'a'), [qw/a b/ ], 'A is member of b (and a)');
	ok($test->remove(group => 'b', member => 'a'),'Remove a from b');
	ok($test->drop(role => 'b'),'Drop b');
	ok($test->drop(role => 'a'),'Drop a');
};

package main;

Test::Role::Pg::Roles->runtests;

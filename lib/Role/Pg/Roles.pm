package Role::Pg::Roles;

use 5.010;
use Moose::Role;
use DBI;
use Digest::MD5 qw/md5_hex/;

has 'roles_dbh' => (
	is => 'ro',
	isa => 'DBI::db',
	lazy_build => 1,
);

sub _build_roles_dbh {
	my $self = shift;
	return $self->dbh if $self->can('dbh');
	return $self->schema->storage->dbh if $self->can('schema');
}

sub create {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my $role = $dbh->quote_identifier($args{role}) or return;
	my $sql = qq{
		CREATE ROLE $role
	};
	my @values;
	if (my $password = $args{password}) {
		$sql .= ' WITH ENCRYPTED PASSWORD ?';
		push @values, $password;
	}
	$self->roles_dbh->do($sql, undef, @values);
}

sub drop {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my $role = $dbh->quote_identifier($args{role}) or return;
	my $sql = qq{
		DROP ROLE $role
	};
	$self->roles_dbh->do($sql);
}

sub add {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my ($group, $member) = map {$dbh->quote_identifier($args{$_}) // return} qw/group member/;
	my $sql = qq{
		GRANT $group TO $member
	};
	$self->roles_dbh->do($sql);
}

sub remove {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my ($group, $member) = map {$dbh->quote_identifier($args{$_}) // return} qw/group member/;
	my $sql = qq{
		REVOKE $group FROM $member
	};
	$self->roles_dbh->do($sql);
}

sub check_user {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my ($user, $password) = map {$args{$_} // return} qw/user password/;
	my $sql = qq{
		SELECT 1 FROM pg_catalog.pg_authid
		WHERE rolname = ? AND rolpassword = ?
	};
	push my @values, $user, 'md5' . md5_hex($password . $user);
	return $self->roles_dbh->selectrow_arrayref($sql, undef, @values) ? 1 : 0;
}

sub roles {
	my ($self, %args) = @_;
	my $sql = q{
		SELECT rolname
		FROM pg_authid a
		WHERE pg_has_role(?, a.oid, 'member')
	};
	my @values = map {$args{$_} // return} qw/user/;

	return [ sort map {shift @$_} @{ $self->roles_dbh->selectall_arrayref($sql, undef, @values) } ];
}

sub member_of {
	my ($self, %args) = @_;
	my ($user, $group) = map {$args{$_} // return} qw/user group/;
	my $roles = $self->roles(user => $user);

	return grep {$group eq $_} @$roles;
}

sub set {
	my ($self, %args) = @_;
	my $dbh = $self->roles_dbh;
	my $role = $dbh->quote_identifier($args{role}) or return;
	my $sql = qq{
		SET ROLE $role
	};
	$self->roles_dbh->do($sql);
}

sub reset {
	my ($self) = @_;
	my $sql = qq{
		RESET ROLE
	};
	$self->roles_dbh->do($sql);
}

1;

__END__

# ABSTRACT: Client Role for handling PostgreSQL Roles

=head1 name

role::pg::roles

=head1 description

this role handles the use of roles in a postgresql database.

=head1 attributes

=head2 roles_dbh

role::pg::roles tries to guess your dbh. if it isn't a standard dbi::db named dbh, or
constructed in a dbix::class schema called schema, you have to return the dbh from
_build_roles_dbh.

=head1 METHODS

=head2 create

 $self->create(role => 'me', password => 'safety');

Creates a role. The role can be seen as either a user or a group.

An optional password can be added. The user is then created with an encrypted password.

=head2 drop

 $self->drop(role => 'me');

Drops a role.

=head2 add

 $self->add(group => 'group', member => 'me');

Adds a member to a group. A member can be a user or a group

=head2 remove

 $self->remove(group => 'group', member => 'me');

Removes a member from a group.

=head2 check_user

 my $roles = $self->check_user(user => 'me', password => 'trust me!');

Checks if there is a user with the given password

=head2 roles

 my $roles = $self->roles(user => 'me');

Returns an arrayref with all the roles the user is a member of.

=head2 member_of

 print "yep" if $self->member_of(user => 'me', group => 'group');

Returns true if user is member of group.

=head2 set

 $self->set(role => 'elvis');

Assume another role.

=head2 reset

 $self->reset;

Back to your old self.

=head1 AUTHOR

Kaare Rasmussen <kaare@cpan.org>.

=head1 COPYRIGHT

Copyright (C) 2014, Kaare Rasmussen

This module is free software; you can redistribute it or modify it
under the same terms as Perl itself.

=cut

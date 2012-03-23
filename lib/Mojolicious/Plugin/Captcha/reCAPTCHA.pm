package Mojolicious::Plugin::Captcha::reCAPTCHA;

# ABSTRACT: use Captcha::reCAPTCHA in Mojolicious apps

use strict;
use warnings;

use Mojo::Base 'Mojolicious::Plugin';
use Captcha::reCAPTCHA;

our $VERSION = 0.03;

sub register {
	my $self = shift;
	my $app  = shift;
	my $conf = shift || {};

	die ref($self), ": need private and public key\n"
		unless $conf->{private_key} and $conf->{public_key};

	$app->attr(
		'recaptcha_obj' => sub {
			Captcha::reCAPTCHA->new;
		},
	);

	$app->attr( recaptcha_private_key => sub { $conf->{private_key} } );
	$app->attr( recaptcha_public_key  => sub { $conf->{public_key} } );

	$app->helper( recaptcha => sub { return shift->app->recaptcha_obj } );
	$app->helper(
		use_recaptcha => sub {
			my $self = shift;
			$self->stash(
				recaptcha_html => $self->recaptcha->get_html( $self->app->recaptcha_public_key ) );
		}
	);
	$app->helper(
		validate_recaptcha => sub {
			my ( $self, $params ) = @_;

			my $result = $self->recaptcha->check_answer(
				$self->app->recaptcha_private_key,    $self->tx->remote_address,
				$params->{recaptcha_challenge_field}, $params->{recaptcha_response_field},
			);

			if ( !$result->{is_valid} ) {
				$self->stash( recaptcha_error => $result->{error} );
			}
		}
	);
} ## end sub register

1;


=pod

=head1 NAME

Mojolicious::Plugin::Captcha::reCAPTCHA - use Captcha::reCAPTCHA in Mojolicious apps

=head1 VERSION

version 0.03

=head1 SYNOPSIS

Provides a Captcha::reCAPTCHA object in your Mojolicious app.

    use Mojolicious::Plugin::Captcha::reCAPTCHA;

    sub startup {
        my $self = shift;

        $self->plugin('Captcha::reCAPTCHA', { 
            private_key => 'the_public_key',
            public_key  => 'your_private_key',
        });
    }

In your mojolicious controller you can control everything by yourself:

    $self->stash(
        recaptcha_html => $self->recaptcha->get_html( $public_key ),
    );

and later

    my $result = $self->recaptcha->check_answer(
        $private_key,
        $ip,
        $value_of_challenge_field,
        $value_of_response_field,
    );

Or you can use the new helper:

=head1 METHODS/HELPERS

=head2 recaptcha

A helper named 'recaptcha' is created that can be used to get the recaptcha object. 

  my $recaptcha_obj = $self->recaptcha;

=head2 use_recaptcha

This helper sets the key "recaptcha_html" in the stash and uses the HTML as the value.

  $self->use_recaptcha;

It uses the public key, you passed in the configuration.

=head2 validate_recaptcha

Handles the validation of the recaptcha. If an error occurs, the stash variable
"recaptcha_error" is set.

  $self->validate_recaptcha( $params );

C<$params> is a hashref with parameters of the HTTP request.

=head1 AUTHORS

=over 4

=item *

Renee Baecker <module@renee-baecker.de>

=item *

Heiko Jansen <jansen@hbz-nrw.de>

=back

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2012 by Hochschulbibliothekszentrum NRW (hbz).

This is free software, licensed under:

  The GNU General Public License, Version 3, June 2007

=cut


__END__


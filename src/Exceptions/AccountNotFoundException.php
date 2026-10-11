<?php

namespace CoyoteCert\Exceptions;

/** The CA has no account for the stored key (RFC 8555 accountDoesNotExist). */
class AccountNotFoundException extends AcmeException {}

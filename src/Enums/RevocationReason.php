<?php

namespace CoyoteCert\Enums;

enum RevocationReason: int
{
    case Unspecified          = 0;
    case KeyCompromise        = 1;
    case CaCompromise         = 2;
    case AffiliationChanged   = 3;
    case Superseded           = 4;
    case CessationOfOperation = 5;
    case CertificateHold      = 6;
    case PrivilegeWithdrawn   = 9;
    case AaCompromise         = 10;
}

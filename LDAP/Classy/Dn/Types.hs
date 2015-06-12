module LDAP.Classy.Dn.Types where

import           Data.List.NonEmpty (NonEmpty)
import           Data.Monoid        (Monoid (mappend, mempty))
import           Data.Semigroup     (Semigroup ((<>)))
import           Data.Text          (Text)

import LDAP.Classy.AttributeType    (AttributeType)

newtype RelativeDn = RelativeDn
  { unRelativeDn :: NonEmpty (AttributeType,Text)
  } deriving (Eq)

-- BUG: Note that our derived equality here doesn't work in all cases
-- because we at least need to treat the relative DNs as sets rather
-- than have the ordering affect equality. There is something in an
-- RFC about this that I'll have to read later.
newtype Dn = Dn { unDn :: [RelativeDn] } deriving (Eq)

instance Semigroup Dn where
  (Dn nel1) <> (Dn nel2) = Dn (nel1 <> nel2)

instance Monoid Dn where
  mappend = (<>)
  mempty  = Dn mempty

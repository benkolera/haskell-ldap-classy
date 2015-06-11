module LDAP.Classy.ParsingUtils where

import Data.Attoparsec.Text (Parser,satisfy,notInClass,inClass)

notInClassP :: String -> Parser Char
notInClassP = satisfy . notInClass

inClassP :: String -> Parser Char
inClassP butts = satisfy . inClass $ butts

invalidStrCharSet :: [Char]
invalidStrCharSet = ",#=+;<>\\\x00"

module LDAP.Classy.ParsingUtils where

import Data.Attoparsec.Text (Parser,satisfy,notInClass,inClass)

notInClassP :: String -> Parser Char
notInClassP = satisfy . notInClass

inClassP :: String -> Parser Char
inClassP = satisfy . inClass 

invalidStrCharSet :: String
invalidStrCharSet = ",#=+;<>\\\x00"

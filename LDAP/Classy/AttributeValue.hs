{-# LANGUAGE OverloadedStrings #-}
module LDAP.Classy.AttributeValue where

import Control.Applicative ((<$>),(<*>),(<|>),pure,(*>))
import Data.Foldable (foldMap,toList)
import Control.Monad (mzero)
import Data.Attoparsec.Text (Parser,eitherResult,feed,parse,option,space,endOfInput,many1,peekChar)
import Data.Semigroup ((<>))
import Data.Text (Text)
import qualified Data.Text as T

import LDAP.Classy.ParsingUtils (invalidStrCharSet,notInClassP,inClassP)

newtype AttributeValue = AttributeValue Text

data DnValuePart = DnValueText Text | DnValueSpecial Char deriving Show

attrValueToText :: Text -> Text
attrValueToText = foldMap dnValuePartText . parseDnTextParts

dnValuePartText :: DnValuePart -> Text
dnValuePartText (DnValueText t)         = t
dnValuePartText (DnValueSpecial '\x00') = ""  -- No one needs that. Haha.
dnValuePartText (DnValueSpecial c)      = "\\" <> T.singleton c

parseDnTextParts :: Text -> [DnValuePart]
parseDnTextParts = either (const []) id . parseDnTextPartsEither

parseDnTextPartsEither :: Text -> Either String [DnValuePart]
parseDnTextPartsEither =
  eitherResult
  . flip feed ""
  . parse dnValueParts

dnValueParts :: Parser [DnValuePart]
dnValueParts = do
  ls <- option Nothing (Just . DnValueSpecial <$> space)
  ps <- innerValueParts
  endOfInput
  pure (toList ls <> ps)

innerValueParts :: Parser [DnValuePart]
innerValueParts = hlpr []
  where
    hlpr acc  = base acc <|> recur acc
    base acc  =
      ((reverse . (:acc) . DnValueSpecial) <$> lastSpace)
      <|> (endOfInput *> pure (reverse acc))
    recur acc = innerValuePartChar >>= hlpr . (:acc)

innerValuePartChar :: Parser DnValuePart
innerValuePartChar =
  innerValueText
  <|> (DnValueSpecial <$> specialChar)
  <|> (DnValueSpecial <$> innerSpace)

innerValueText :: Parser DnValuePart
innerValueText = DnValueText . T.pack <$> many1 innerValueStrChar

innerValueStrChar :: Parser Char
innerValueStrChar = innerSpace <|> notInClassP (invalidStrCharSet <> " ")

specialChar :: Parser Char
specialChar = inClassP invalidStrCharSet

innerSpace :: Parser Char
innerSpace = do
  s <- space
  c <- peekChar
  case c of
    Just _ -> return s
    _      -> mzero

lastSpace :: Parser Char
lastSpace = do
  s <- space
  c <- peekChar
  case c of
    Nothing -> return s
    _       -> mzero

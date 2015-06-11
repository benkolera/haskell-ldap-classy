{-# LANGUAGE OverloadedStrings #-}
module LDAP.Classy.AttributeValue where

import Control.Applicative ((<$>),(<|>),pure,(*>))
import Control.Monad.Reader (ReaderT,runReaderT,lift,ask)
import Data.Foldable (foldMap,toList)
import Data.List (nub)
import Control.Monad (mzero)
import Data.Attoparsec.Text (Parser,eitherResult,feed,parse,option,space,endOfInput,many1,peekChar)
import Data.Semigroup ((<>))
import Data.Text (Text)
import qualified Data.Text as T

import LDAP.Classy.ParsingUtils (invalidStrCharSet,notInClassP,inClassP)

data DnValuePart = DnValueText Text | DnValueSpecial Char deriving Show

escapeAttrValueTextExtraEscape :: String -> Text -> Text
escapeAttrValueTextExtraEscape extraSpecialChars =
  foldMap dnValuePartText . parseDnTextParts invalidChars
  where
    invalidChars = nub $ invalidStrCharSet <> " " <> extraSpecialChars

escapeAttrValueText :: Text -> Text
escapeAttrValueText = escapeAttrValueTextExtraEscape ""

dnValuePartText :: DnValuePart -> Text
dnValuePartText (DnValueText t)         = t
dnValuePartText (DnValueSpecial '\x00') = ""  -- No one needs that. Haha.
dnValuePartText (DnValueSpecial c)      = "\\" <> T.singleton c

parseDnTextParts :: String -> Text -> [DnValuePart]
parseDnTextParts invalidSet =
  either (const []) id . parseDnTextPartsEither invalidSet

parseDnTextPartsEither :: String -> Text -> Either String [DnValuePart]
parseDnTextPartsEither invalidSet =
  eitherResult
  . flip feed ""
  . parse (runReaderT dnValueParts invalidSet)

dnValueParts :: ReaderT String Parser [DnValuePart]
dnValueParts = do
  ls <- lift $ option Nothing (Just . DnValueSpecial <$> space)
  ps <- innerValueParts
  lift endOfInput
  pure (toList ls <> ps)

innerValueParts :: ReaderT String Parser [DnValuePart]
innerValueParts = hlpr []
  where
    hlpr acc  = base acc <|> recur acc
    base acc  =
      ((reverse . (:acc) . DnValueSpecial) <$> lift lastSpace)
      <|> (lift endOfInput *> pure (reverse acc))
    recur acc = innerValuePartChar >>= hlpr . (:acc)

innerValuePartChar :: ReaderT String Parser DnValuePart
innerValuePartChar =
  innerValueText
  <|> (DnValueSpecial <$> specialChar)
  <|> (DnValueSpecial <$> lift innerSpace)

innerValueText :: ReaderT String Parser DnValuePart
innerValueText = DnValueText . T.pack <$> many1 innerValueStrChar

innerValueStrChar :: ReaderT String Parser Char
innerValueStrChar = lift innerSpace <|> (ask >>= lift . notInClassP)

specialChar :: ReaderT String Parser Char
specialChar = ask >>= lift . inClassP 

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

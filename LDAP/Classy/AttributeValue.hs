{-# LANGUAGE OverloadedStrings #-}
module LDAP.Classy.AttributeValue where

import           Control.Applicative      ((<|>))
import           Control.Monad            (mzero)
import           Control.Monad.Reader     (ReaderT, ask, lift, runReaderT)
import           Data.Attoparsec.Text     (Parser, eitherResult, endOfInput,
                                           feed, many1, option, parse, peekChar,
                                           space)
import qualified Data.ByteString.Base16   as BS16
import qualified Data.ByteString.Char8    as BS8
import           Data.Foldable            (toList)
import           Data.List                (nub)
import           Data.Semigroup           ((<>))
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as T (decodeUtf8)

import           LDAP.Classy.ParsingUtils (inClassP, invalidStrCharSet,
                                           notInClassP)

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
-- We're okay to use ByteString.Char8 here since specialChar parses no non-ascii characters
dnValuePartText (DnValueSpecial c)      = "\\" <> T.decodeUtf8 (BS16.encode . BS8.pack $ [c])

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

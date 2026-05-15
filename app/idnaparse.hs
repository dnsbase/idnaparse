-- | idnaparse -- parse a stream of host-style domain names against the
-- IDNA-aware presentation parser and emit one JSON record per input.
--
-- Reads UTF-8 lines from stdin, one name per line.  Each non-discarded
-- line produces a JSON object on stdout:
--
-- * Successful parse + unparse:
--
--     @{ "input"        : { "text": ..., "forms": [...] }
--      , "presentation" : ...   -- canonical RFC 1035 form
--      , "output"       : { "text": ..., "forms": [...] }
--      , "fakes"        : [...] -- present iff at least one FAKEA label appears
--      }@
--
--   @input.forms@ classifies the label forms seen on input (after mappings);
--   @output.forms@ classifies the labels produced on output.
--   A-labels in the input may become U-labels on output.
--   With crossl-label BIDI rule violations, and ASCII fallback enabled,
--   U-labels in the input may become A-labels on output.
--
-- * Parse failure:
--
--     @{ "input": { "text": ..., "error": {...} } }@
--
-- * Unparse failure (parse succeeded, unparse rejected):
--
--     @{ "input"        : { "text": ..., "forms": [...] }
--      , "presentation" : ...
--      , "output"       : { "error": {...} }
--      , "fakes"        : [...] -- present iff at least one FAKEA label appears
--      }@
--
-- Discards (overlong lines, ill-formed UTF-8) produce no row; they are
-- counted in the optional summary.
--
-- See @--help@ for CLI flags.
module Main (main) where

import qualified Data.ByteString as BSStrict
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as Enc
import qualified Streaming.ByteString.Char8 as Q
import qualified Streaming.Prelude as S
import Control.Monad ((>=>), unless, when)
import Data.Bits ((.&.), unsafeShiftR)
import qualified Data.List as List
import Data.IORef
import Data.Map.Strict (Map)
import Data.Word (Word8)
import Streaming (Stream, Of(..), inspect, lift)
import System.IO (BufferMode(..), hSetBinaryMode, hSetBuffering, stdin, stdout)

import Options.Applicative

import Text.IDNA2008
    ( AceReason(..)
    , BidiRuleViolation
    , IdnaError(..)
    , IdnaFlags(..)
    , LabelForm(..)
    , LabelFormSet
    , LabelReason(..)
    , defaultIdnaFlags
    , domainToAscii
    , getLabelForms
    , idnLabelForms
    , parseDomainOpts
    , parseIdnaFlagsStr
    , parseLabelFormSetStr
    , unparseDomainOpts
    , (<->)
    )

----------------------------------------------------------------------
-- Constants
----------------------------------------------------------------------

-- | Worst-case length of a presentation-form fully-qualified name
-- with maximal escaping.
nameLimit :: Int
nameLimit = 1024

----------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------

data Options = Options
    { optForms :: !LabelFormSet
    , optFlags :: !IdnaFlags
    , optSummary :: !Bool
    , optNoRows :: !Bool
    }

optionsParser :: Parser Options
optionsParser = Options
    <$> option formsReader
        ( long "forms"
       <> metavar "FORMS"
       <> value idnLabelForms
       <> showDefault
       <> help formsHelp )
    <*> option idnaFlagsReader
        ( long "opts"
       <> metavar "OPTS"
       <> value defaultIdnaFlags
       <> showDefault
       <> help optsHelp )
    <*> switch
        ( long "summary"
       <> help "Emit a trailing summary record" )
    <*> switch
        ( long "no-rows"
       <> help "Suppress per-row records (combine with --summary)" )

formsHelp :: String
formsHelp =
    "Permitted label-form tokens (comma-separated, +/- prefix); \
    \see --explain-forms."

opts :: ParserInfo Options
opts = info (optionsParser <**> helper
                           <**> explainFormsFlag
                           <**> explainOptsFlag)
    ( fullDesc
   <> progDesc "Parse domain names from stdin (one per line) and emit \
               \one JSON record per name on stdout."
   <> header "idnaparse - IDNA-aware DNS-name lint and reporter" )

-- | --explain-forms: print the label-form glossary and exit.  Kept
-- separate from --help so the default option list stays compact;
-- callers who want the full vocabulary opt in explicitly.
explainFormsFlag :: Parser (a -> a)
explainFormsFlag = infoOption formsExplainText
    ( long "explain-forms"
   <> help "Print the label-form glossary and exit" )

-- | --explain-opts: print the IDNA-options glossary and exit.
-- Covers validation checks, input mappings, the Bidi rule
-- mechanism, the emoji relaxation, and the ASCII fallback policy
-- in one place.
explainOptsFlag :: Parser (a -> a)
explainOptsFlag = infoOption optsExplainText
    ( long "explain-opts"
   <> help "Print the IDNA-options glossary and exit" )

formsExplainText :: String
formsExplainText = unlines
    [ "SYNTAX"
    , "  Comma-separated tokens passed to --forms.  Tokens are"
    , "  case-insensitive; 3-character prefix matching is accepted"
    , "  (e.g. 'alab' for 'alabel', 'wild' for 'wildlabel')."
    , "  Default --forms value: \"default\"."
    , ""
    , "  Sign prefixes: \"-X\" subtracts; \"+X\" or unprefixed \"X\""
    , "  adds.  If the FIRST token starts with \"+\" or \"-\", the"
    , "  running result is seeded with \"default\" and your tokens"
    , "  tweak it.  Otherwise the running result starts empty and"
    , "  your tokens replace the default."
    , ""
    , "PRESETS (composite tokens that expand to a fixed set of bits)"
    , "  idn         LDH | ALABEL | ULABEL  (also: 'default' or 'strict')"
    , "  host        idn | RLDH | FAKEA"
    , "  all         host | ATTRLEAF | OCTET | WILDLABEL"
    , "LABEL FORMS"
    , "  LDH        Letter-Digit-Hyphen.  Lowercase a-z, digits 0-9, and"
    , "             '-'.  No leading or trailing hyphen.  The conventional"
    , "             hostname alphabet."
    , "  RLDH       Reserved LDH.  LDH-shaped label with '--' at positions"
    , "             3-4 that is NOT 'xn--'-prefixed.  Reserved by RFC 5890;"
    , "             typically these are pre-IDN registrations (such as,"
    , "             \"cd--shelves\", \"l---l\") that happen to share the"
    , "             'X--Y' shape without being A-labels."
    , "  ALABEL     IDNA A-label: an 'xn--' label whose Punycode body"
    , "             decodes to a valid U-label and re-encodes to the same"
    , "             bytes (under alabel-check; without it, every well-formed"
    , "             'xn--' LDH label is an ALABEL).  See --explain-opts."
    , "  FAKEA      'xn--' LDH label that fails the strict A-label"
    , "             round-trip test (bad Punycode, decoded form fails U-label"
    , "             validation, or re-encoded form differs).  Only produced"
    , "             under alabel-check."
    , "  ULABEL     U-label: input contains at least one non-ASCII codepoint"
    , "             admitted by IDNA2008; encoded to its A-label form on the"
    , "             wire."
    , "  ATTRLEAF   LDH-shaped label whose first byte is '_'.  Used for"
    , "             RFC 8552 attribute-leaf names (such as, '_25._tcp.example')."
    , "  OCTET      A label that's not (R)LDH: either the bytes include non-LDH"
    , "             values (control bytes, '_' outside an ATTRLEAF position,"
    , "             bytes >= 0x80, ...), or the input used backslash escapes"
    , "             to force literal interpretation of bytes that might"
    , "             otherwise be LDH."
    , "  WILDLABEL  A label consisting of a single '*' byte.  Distinct from"
    , "             OCTET so that callers can admit or reject it"
    , "             independently."
    , "  LAXULABEL  For debugging only, IDNA-disallowed Unicode label that"
    , "             encodes to or decodes from a plausible-looking FAKEA label."
    , "REFERENCES"
    , "  IDNA2008:  RFC 5890-5895"
    , "  Punycode:  RFC 3492"
    , "  Library:   https://github.com/dnsbase/idna2008"
    ]

optsExplainText :: String
optsExplainText = unlines
    [ "IDNA OPTIONS"
    , "  Comma-separated tokens passed to --opts.  Tokens are"
    , "  case-insensitive; 3-character prefix matching is accepted."
    , "  Default --opts value: \"default\"."
    , ""
    , "  Sign prefixes: \"-X\" subtracts; \"+X\" or unprefixed \"X\""
    , "  adds (\"+\" is the implicit default for additive operations)."
    , "  If the FIRST token starts with \"+\" or \"-\", the running"
    , "  result is seeded with \"default\" and your tokens tweak it"
    , "  (e.g. \"+emoji-ok\" means \"default plus emoji-ok\")."
    , "  Otherwise the running result starts empty and your tokens"
    , "  replace the default (e.g. \"map-case,map-nfc\" yields just"
    , "  those two flags)."
    , ""
    , "VALIDATION CHECKS  (on under \"default\")"
    , ""
    , "  alabel-check  (alias: xncheck)"
    , "      Strict A-label round-trip.  An \"xn--\"-prefixed label whose"
    , "      Punycode body doesn't decode to a valid U-label and re-encode"
    , "      to the same bytes is reported as FAKEA rather than ALABEL."
    , ""
    , "  nfc-check"
    , "      Require Unicode Normalization Form C on U-labels (RFC 5891"
    , "      section 5.3).  Labels with combining marks in non-canonical"
    , "      order, or decomposed sequences with a precomposed equivalent,"
    , "      are rejected."
    , ""
    , "  bidi-check"
    , "      Apply RFC 5893 Bidi rules.  Right-to-left scripts (Hebrew,"
    , "      Arabic, ...) carry a reading direction that bidirectional-"
    , "      text engines honour when laying out a paragraph.  Mixing"
    , "      right-to-left labels with left-to-right ones in a single"
    , "      domain name leaves room for visual reordering -- the rules"
    , "      constrain what a domain may contain so the layout stays"
    , "      unambiguous."
    , ""
    , "      Per label: an individual right-to-left label must be"
    , "      self-consistent (no stray left-to-right characters in the"
    , "      middle, no mixing of European and Arabic-Indic digits, and"
    , "      so on).  Once any label in the name is right-to-left, every"
    , "      other label -- including pure left-to-right ones -- must"
    , "      also pass the rules.  Catches mixtures like"
    , "      \"_tcp.<arabic-label>.example\": \"_tcp\" is fine on its own,"
    , "      but it starts with an underscore, and the rules forbid an"
    , "      underscore-leading label in the same domain as a right-to-"
    , "      left label."
    , ""
    , "      Names that fail are reported as errors, with the offending"
    , "      label index and the specific rule that failed (e.g."
    , "      \"BidiRule1FirstNotLRAL\")."
    , ""
    , "INPUT MAPPINGS  (RFC 5895; off under \"default\")"
    , ""
    , "  map-dots"
    , "      Treat the East Asian period characters (the ideographic"
    , "      period and its fullwidth and halfwidth variants) as label"
    , "      separators, just like '.'."
    , ""
    , "  map-case"
    , "      Lowercase the input.  ASCII A-Z always, and also other"
    , "      letters with a known lowercase form when they appear inside"
    , "      a label that contains non-ASCII characters."
    , ""
    , "  map-width"
    , "      Convert fullwidth and halfwidth characters to their normal-"
    , "      width form.  Fullwidth Latin letters become ordinary ASCII"
    , "      letters, and halfwidth katakana becomes regular katakana."
    , "      Implies map-dots so the fullwidth and halfwidth period"
    , "      characters act as separators."
    , ""
    , "  map-nfc"
    , "      Combine letter-and-accent sequences into single characters"
    , "      where possible.  Affects only labels with non-ASCII"
    , "      characters."
    , ""
    , "  Aliases: cmap = map-case, dmap = map-dots, nmap = map-nfc,"
    , "  wmap = map-width."
    , ""
    , "RELAXATIONS"
    , ""
    , "  emoji-ok"
    , "      Admit non-ASCII codepoints carrying the Unicode Emoji property"
    , "      even when otherwise disallowed by IDNA2008.  Applies both at"
    , "      parse time (the label classifies as ULABEL/ALABEL instead of"
    , "      FAKEA) and at render time (a strictly-round-tripping ACE"
    , "      label whose body decodes to emoji renders as the codepoint)."
    , "      Useful when analysing real-world IDN data that includes emoji"
    , "      registrations."
    , ""
    , "PRESENTATION POLICY"
    , ""
    , "  ascii-fallback"
    , "      Implies bidi-check.  When the cross-label Bidi rules would"
    , "      reject a name, render it in A-label form (every label as"
    , "      ASCII) instead of erroring.  Useful for display contexts"
    , "      where the goal is \"show the user something readable\";"
    , "      strict callers (registry tools, conformance validators)"
    , "      should not enable this -- they want the error."
    , ""
    , "      With validation enabled (the default), an ALABEL in"
    , "      the \"renderedForms\" array is the signal that the"
    , "      cross-label Bidi rules prevented the U-label form:"
    , "      the renderer's Unicode-preferred tiebreak would have"
    , "      picked ULABEL if the rules had not forced the fallback."
    , "      Comparison against the \"forms\" array (parser-time"
    , "      classification) identifies which specific labels were"
    , "      originally Unicode."
    , ""
    , "PRESETS"
    , "  default      alabel-check, nfc-check, bidi-check.  This is the"
    , "               default value of --opts."
    , "  map          The four input mappings above."
    , ""
    , "REFERENCES"
    , "  RFC 5891:  https://www.rfc-editor.org/rfc/rfc5891  (IDNA protocol)"
    , "  RFC 5893:  https://www.rfc-editor.org/rfc/rfc5893  (Bidi rules)"
    , "  RFC 5895:  https://www.rfc-editor.org/rfc/rfc5895  (input mappings)"
    ]

----------------------------------------------------------------------
-- Forms / flags parsers (CLI value readers)
----------------------------------------------------------------------

formsReader :: ReadM LabelFormSet
formsReader = eitherReader (parseLabelFormSetStr idnLabelForms)

idnaFlagsReader :: ReadM IdnaFlags
idnaFlagsReader = eitherReader (parseIdnaFlagsStr defaultIdnaFlags)

optsHelp :: String
optsHelp =
    "IDNA option tokens (comma-separated, +/- prefix); \
    \see --explain-opts."

----------------------------------------------------------------------
-- Counters
----------------------------------------------------------------------

data Counters = Counters
    { cOk       :: !(IORef Int)
    , cFail     :: !(IORef Int)
    , cOverlong :: !(IORef Int)
    , cBadUtf8  :: !(IORef Int)
    , cForms    :: !(IORef (Map BS.ByteString Int))
    , cReasons  :: !(IORef (Map BS.ByteString Int))
    }

newCounters :: IO Counters
newCounters = Counters
    <$> newIORef 0 <*> newIORef 0 <*> newIORef 0 <*> newIORef 0
    <*> newIORef Map.empty <*> newIORef Map.empty

bumpInt :: IORef Int -> IO ()
bumpInt ref = modifyIORef' ref (+ 1)
{-# INLINE bumpInt #-}

bumpKey :: IORef (Map BS.ByteString Int) -> BS.ByteString -> IO ()
bumpKey ref k = modifyIORef' ref (Map.insertWith (+) k 1)
{-# INLINE bumpKey #-}

----------------------------------------------------------------------
-- LabelForm -> sorted list of name-strings
----------------------------------------------------------------------

-- | Render a single 'LabelForm' to its canonical name.  Defers to
-- the library's 'Show' instance, which is authoritative -- a new
-- form constructor surfaces here without any app-side update.
formName :: LabelForm -> BS.ByteString
formName = BS.pack . show

-- | Per-row deduplicated form names.  Used by the summary counter:
-- each distinct form contributes one bump per input row regardless
-- of how many labels carried it.
uniqueFormNames :: [LabelForm] -> [BS.ByteString]
uniqueFormNames = map formName . List.nub

----------------------------------------------------------------------
-- IdnaError / reason classification
----------------------------------------------------------------------

-- | Description of the @"error"@ object's payload: the @reason@
-- vocabulary and any auxiliary fields.
data ErrorRec = ErrorRec
    { erReason :: !BS.ByteString
    , erLabel  :: !(Maybe Int)
    , erCp     :: !(Maybe Int)
    , erLength :: !(Maybe Int)
    , erForm   :: !(Maybe BS.ByteString)
    , erRule   :: !(Maybe BS.ByteString)
    }

emptyError :: BS.ByteString -> ErrorRec
emptyError r = ErrorRec r Nothing Nothing Nothing Nothing Nothing

withLabel :: ErrorRec -> Int -> ErrorRec
withLabel e n = e { erLabel = Just n }

classifyErr :: IdnaError -> ErrorRec
classifyErr = \case
    ErrEmptyLabel loc           ->
        emptyError "EmptyLabel" `withLabel` loc
    ErrLabelTooLong loc n       ->
        (emptyError "LabelTooLong" `withLabel` loc)
            { erLength = Just n }
    ErrNameTooLong n            ->
        (emptyError "NameTooLong") { erLength = Just n }
    ErrBadEscape loc _          ->
        emptyError "BadEscape" `withLabel` loc
    ErrInvalidUtf8 loc _        ->
        emptyError "InvalidUtf8" `withLabel` loc
    ErrCodepointTooLarge loc cp ->
        (emptyError "CodepointTooLarge" `withLabel` loc)
            { erCp = Just cp }
    ErrUnpresentableLabel loc   ->
        emptyError "UnpresentableLabel" `withLabel` loc
    ErrFormNotAllowed loc fm    ->
        (emptyError "FormNotAllowed" `withLabel` loc)
            { erForm = Just (BS.pack (show fm)) }
    ErrLabelInvalid loc r       ->
        let er = classifyU r
        in  er { erLabel = Just loc }
    ErrAceInvalid loc r         ->
        let er = classifyA r
        in  er { erLabel = Just loc }
    ErrPunycodeOverflow loc     ->
        emptyError "PunycodeOverflow" `withLabel` loc
    ErrCrossLabelBidi i rule    ->
        (emptyError "CrossLabelBidi" `withLabel` i)
            { erRule = Just (showBidiRule rule) }

classifyU :: LabelReason -> ErrorRec
classifyU = \case
    DisallowedCodepoint cp ->
        (emptyError "DisallowedCodepoint") { erCp = Just cp }
    ContextRule cp         ->
        (emptyError "ContextRule")         { erCp = Just cp }
    NotNFC                 -> emptyError "NotNFC"
    LabelBidi rule         ->
        (emptyError "BidiViolation") { erRule = Just (showBidiRule rule) }
    HyphenViolation        -> emptyError "HyphenViolation"
    LeadingCombiningMark cp ->
        (emptyError "LeadingCombiningMark") { erCp = Just cp }

classifyA :: AceReason -> ErrorRec
classifyA = \case
    BadPunycode         -> emptyError "BadPunycode"
    RoundTripMismatch   -> emptyError "RoundTripMismatch"
    DecodedInvalid r    -> classifyU r

-- | Render a 'BidiRuleViolation' as the constructor name (e.g.
-- @\"BidiRule1FirstNotLRAL\"@), so JSON consumers can grep for
-- it without us having to coin our own vocabulary.
showBidiRule :: BidiRuleViolation -> BS.ByteString
showBidiRule = BS.pack . show

----------------------------------------------------------------------
-- main
----------------------------------------------------------------------

main :: IO ()
main = do
    o <- execParser opts
    hSetBinaryMode stdin  True
    hSetBinaryMode stdout True
    hSetBuffering  stdout (BlockBuffering Nothing)
    counters <- newCounters
    S.mapM_ (processOne counters o (optFlags o))
            (textLines counters Q.stdin)
    when (optSummary o) (emitSummary counters)

processOne :: Counters -> Options -> IdnaFlags -> T.Text -> IO ()
processOne !c !o !idnaFlags !name =
    case parseDomainOpts (optForms o) idnaFlags name of
      Left e -> emitParseFailure (classifyErr e)
      Right (dn, parseInfo) -> do
        let !inSeq      = getLabelForms parseInfo
            !inFormNms  = map formName inSeq
            !pres       = domainToAscii dn
        -- Form counters reflect the parser's input characterisation;
        -- bump them on parse success regardless of whether the
        -- unparse step then succeeded.  The FAKEA per-label
        -- diagnostic is gathered for the row's @fakes@ JSON field
        -- but does /not/ feed 'cReasons': FAKEA admitted on input
        -- is not a failure reason, and FAKEA rejected on input
        -- already surfaces under the parse-failure reason.
        mapM_ (bumpKey (cForms c)) (uniqueFormNames inSeq)
        let !mFake = if FAKEA `elem` inSeq
                       then collectFake (optForms o) idnaFlags name
                       else Nothing
        case unparseDomainOpts (optForms o) idnaFlags dn of
          Left e ->
              emitUnparseFailure inFormNms pres mFake (classifyErr e)
          Right (output, renderInfo) -> do
              -- 'inSeq' is the parser's per-label classification in
              -- label order; 'outSeq' is the unparser's.  They
              -- differ when 'ASCIIFALLBACK' downgrades a U-label to
              -- its ACE form: 'input.forms' carries 'ULABEL',
              -- 'output.forms' carries 'ALABEL'.
              let !outSeq = getLabelForms renderInfo
              bumpInt (cOk c)
              unless (optNoRows o) $
                  BB.hPutBuilder stdout
                      (successRow name inFormNms pres
                                  output (map formName outSeq)
                                  mFake
                       <> BB.char7 '\n')
  where
    emitParseFailure !er = do
        bumpInt (cFail c)
        bumpKey (cReasons c) (erReason er)
        unless (optNoRows o) $
            BB.hPutBuilder stdout (parseFailureRow name er <> BB.char7 '\n')

    emitUnparseFailure !inForms !pres !mFake !er = do
        bumpInt (cFail c)
        bumpKey (cReasons c) (erReason er)
        unless (optNoRows o) $
            BB.hPutBuilder stdout
                (unparseFailureRow name inForms pres mFake er <> BB.char7 '\n')

-- | If the original parse classified at least one label as @FAKEA@,
-- re-parse with @FAKEA@ stripped from the allowed set so the parser
-- surfaces the precise 'AceReason' via @ErrAceInvalid@.  Returns
-- the first failing label's reason, or 'Nothing' on the (impossible)
-- case where the masked parse doesn't fail at all.
collectFake :: LabelFormSet -> IdnaFlags -> T.Text -> Maybe ErrorRec
collectFake forms idnaFlags name =
    case parseDomainOpts (forms <-> FAKEA) idnaFlags name of
      Left e@(ErrAceInvalid _ _) -> Just (classifyErr e)
      _                          -> Nothing

----------------------------------------------------------------------
-- Row builders
----------------------------------------------------------------------

-- | Parse + unparse both succeeded.  Both forms arrays carry the
-- per-label classification at the relevant phase; they differ when
-- 'ASCIIFALLBACK' fires (typically @ULABEL@ in @input.forms@,
-- @ALABEL@ in @output.forms@).
successRow :: T.Text
           -> [BS.ByteString]    -- ^ Parser's per-label classification
           -> T.Text             -- ^ Presentation form (canonical ASCII)
           -> T.Text             -- ^ Rendered output text
           -> [BS.ByteString]    -- ^ Unparser's per-label classification
           -> Maybe ErrorRec     -- ^ FAKEA per-label diagnostic
           -> BB.Builder
successRow input inForms pres output outForms mFake =
       BB.byteString "{\"input\":"        <> inputObject input inForms
    <> BB.byteString ",\"presentation\":" <> jsonString pres
    <> BB.byteString ",\"output\":"       <> outputObject output outForms
    <> maybe mempty
             (\er -> BB.byteString ",\"fakes\":["
                  <> errorObject er
                  <> BB.byteString "]")
             mFake
    <> BB.char7 '}'

-- | Parse failed: only the input text and the error.
parseFailureRow :: T.Text -> ErrorRec -> BB.Builder
parseFailureRow input er =
       BB.byteString "{\"input\":{\"text\":"
    <> jsonString input
    <> BB.byteString ",\"error\":"
    <> errorObject er
    <> BB.byteString "}}"

-- | Parse succeeded but unparse failed (e.g. cross-label Bidi
-- without @ASCIIFALLBACK@).  The input side carries the parser's
-- classification; the output side carries only the error.  The
-- FAKEA per-label diagnostic, when present, comes through too --
-- it characterises the parsed input, which the unparse failure
-- doesn't invalidate.
unparseFailureRow :: T.Text
                  -> [BS.ByteString]    -- ^ Parser's per-label classification
                  -> T.Text             -- ^ Presentation form
                  -> Maybe ErrorRec     -- ^ FAKEA per-label diagnostic
                  -> ErrorRec
                  -> BB.Builder
unparseFailureRow input inForms pres mFake er =
       BB.byteString "{\"input\":"        <> inputObject input inForms
    <> BB.byteString ",\"presentation\":" <> jsonString pres
    <> BB.byteString ",\"output\":{\"error\":"
    <> errorObject er
    <> BB.byteString "}"
    <> maybe mempty
             (\fake -> BB.byteString ",\"fakes\":["
                    <> errorObject fake
                    <> BB.byteString "]")
             mFake
    <> BB.char7 '}'

inputObject :: T.Text -> [BS.ByteString] -> BB.Builder
inputObject text forms =
       BB.byteString "{\"text\":"  <> jsonString text
    <> BB.byteString ",\"forms\":" <> jsonStringArray forms
    <> BB.char7 '}'

outputObject :: T.Text -> [BS.ByteString] -> BB.Builder
outputObject text forms =
       BB.byteString "{\"text\":"  <> jsonString text
    <> BB.byteString ",\"forms\":" <> jsonStringArray forms
    <> BB.char7 '}'

-- | Render an 'ErrorRec' as a JSON object @{ "reason":..., "label"?:..., ... }@.
-- Optional fields appear only when present.
errorObject :: ErrorRec -> BB.Builder
errorObject er =
       BB.byteString "{\"reason\":\""
    <> BB.byteString (erReason er)
    <> BB.char7 '"'
    <> maybe mempty intField (("label" ,) <$> erLabel  er)
    <> maybe mempty intField (("cp"    ,) <$> erCp     er)
    <> maybe mempty intField (("length",) <$> erLength er)
    <> maybe mempty strField (("form"  ,) <$> erForm   er)
    <> maybe mempty strField (("rule"  ,) <$> erRule   er)
    <> BB.char7 '}'
  where
    intField (k, v) =
           BB.byteString ",\""
        <> BB.byteString k
        <> BB.byteString "\":"
        <> BB.intDec v
    strField (k, v) =
           BB.byteString ",\""
        <> BB.byteString k
        <> BB.byteString "\":\""
        <> BB.byteString v
        <> BB.char7 '"'

----------------------------------------------------------------------
-- Summary record
----------------------------------------------------------------------

emitSummary :: Counters -> IO ()
emitSummary c = do
    ok       <- readIORef (cOk c)
    bad      <- readIORef (cFail c)
    over     <- readIORef (cOverlong c)
    badutf8  <- readIORef (cBadUtf8 c)
    formsM   <- readIORef (cForms c)
    reasonsM <- readIORef (cReasons c)
    BB.hPutBuilder stdout
        (   BB.byteString "{\"summary\":{\"ok\":"
         <> BB.intDec ok
         <> BB.byteString ",\"fail\":"
         <> BB.intDec bad
         <> BB.byteString ",\"discard\":{\"overlong\":"
         <> BB.intDec over
         <> BB.byteString ",\"badutf8\":"
         <> BB.intDec badutf8
         <> BB.byteString "},\"forms\":"
         <> jsonIntMap formsM
         <> BB.byteString ",\"reasons\":"
         <> jsonIntMap reasonsM
         <> BB.byteString "}}\n")

-- | Render a @Map ByteString Int@ as a JSON object with sorted keys.
jsonIntMap :: Map BS.ByteString Int -> BB.Builder
jsonIntMap m
    | Map.null m = BB.byteString "{}"
    | otherwise  =
           BB.char7 '{'
        <> mconcat (zipWith pair (Map.toAscList m) (False : repeat True))
        <> BB.char7 '}'
  where
    pair (k, v) sep =
           (if sep then BB.char7 ',' else mempty)
        <> BB.char7 '"'
        <> BB.byteString k
        <> BB.byteString "\":"
        <> BB.intDec v

----------------------------------------------------------------------
-- JSON encoding helpers
----------------------------------------------------------------------

jsonString :: T.Text -> BB.Builder
jsonString !t =
    BB.char7 '"' <> T.foldr step mempty t <> BB.char7 '"'
  where
    step !c !acc = escapeChar c <> acc

escapeChar :: Char -> BB.Builder
escapeChar !c
    | c == '"'          = BB.byteString "\\\""
    | c == '\\'         = BB.byteString "\\\\"
    | c == '\b'         = BB.byteString "\\b"
    | c == '\t'         = BB.byteString "\\t"
    | c == '\n'         = BB.byteString "\\n"
    | c == '\f'         = BB.byteString "\\f"
    | c == '\r'         = BB.byteString "\\r"
    | fromEnum c < 0x20 = uHex (fromEnum c)
    | otherwise         = BB.charUtf8 c

uHex :: Int -> BB.Builder
uHex !n =
       BB.byteString "\\u00"
    <> BB.word8 (hexNibble (n `unsafeShiftR` 4))
    <> BB.word8 (hexNibble (n .&. 0x0F))

hexNibble :: Int -> Word8
hexNibble !n
    | n < 10    = fromIntegral (0x30 + n)             -- '0'..'9'
    | otherwise = fromIntegral (0x57 + n)             -- 'a'..'f'

-- | Render a list of (already-ASCII) ByteStrings as a JSON array of
-- string literals.  Used for the @forms@ field, which only contains
-- the canonical form names ("LDH", "ULABEL", etc.) -- no escaping
-- needed.
jsonStringArray :: [BS.ByteString] -> BB.Builder
jsonStringArray xs =
       BB.char7 '['
    <> mconcat (zipWith one xs (False : repeat True))
    <> BB.char7 ']'
  where
    one s sep =
           (if sep then BB.char7 ',' else mempty)
        <> BB.char7 '"'
        <> BB.byteString s
        <> BB.char7 '"'

----------------------------------------------------------------------
-- Stream<>line<>Text
----------------------------------------------------------------------

textLines :: Counters -> Q.ByteStream IO () -> Stream (Of T.Text) IO ()
textLines !c = decode . Q.lines
  where
    decode = go

    go = lift . inspect >=> \case
        Left _  -> pure ()
        Right l -> do
            (bs :> rest) <-
                lift $ Q.toStrict
                     $ Q.drained
                     $ Q.splitAt (fromIntegral (nameLimit + 1)) l
            if BSStrict.length bs > nameLimit
              then lift (bumpInt (cOverlong c))
              else case Enc.decodeUtf8' bs of
                Right t -> S.yield t
                Left _  -> lift (bumpInt (cBadUtf8 c))
            go rest

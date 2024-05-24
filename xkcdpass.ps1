<#
.SYNOPSIS
    xkckpass.ps1 is a utility to generaty easily remembered, but difficult to guess (or brute force) passphrases.
.DESCRIPTION
    xkcdpass.ps1 will output a list of secure passwords (not easily guessed or brute forced) for use by end users or support folks.
.PARAMETER preset
    Use one of the defaut presets:
    	STD (Standard):
    		numpwds=3
    		numwords=3
    		minwordlen=5
    		maxwordlen=8
    		casetrans=capitalize
    		sepchars="@%^&*_+~?'/"
    		paddigitspre=0
    		paddigitspost=2
    		padtype=fixed
    		padlength=0
    		padchars="!@$%^&=~?"
    		padcharspre=1
    		padcharspost=1

    	WSE (Windows Server Essentials):
    		numpwds=3
    		numwords=3
    		minwordlen=5
    		maxwordlen=8
    		casetrans=capitalize
    		sepchars="@%^&*_+~?'/"
    		paddigitspre=0
    		paddigitspost=2
    		padtype=fixed
    		padlength=0
    		padchars="!@$%^&=~?"
    		padcharspre=1
    		padcharspost=1

    	ALT (Alternate):
    		numpwds=3
    		numwords=3
    		minwordlen=5
    		maxwordlen=8
    		casetrans=capitalize
    		sepchars="@%^&*_+~?'/"
    		paddigitspre=0
    		paddigitspost=2
    		padtype=fixed
    		padlength=0
    		padchars="!@$%^&=~?"
    		padcharspre=1
    		padcharspost=1

    	STR (Strict 56 bit):
    		numpwds=3
    		numwords=3
    		minwordlen=5
    		maxwordlen=8
    		casetrans=capitalize
    		sepchars="@%^&*_+~?'/"
    		paddigitspre=0
    		paddigitspost=2
    		padtype=fixed
    		padlength=0
    		padchars="!@$%^&=~?"
    		padcharspre=1
    		padcharspost=1
.PARAMETER dict
    Specifies a path to a wordlist. This wordlist should contain one word per line.
.PARAMETER numpwds
    An integer value for the number or passphrases to return.
.PARAMETER numwords
    An integer value for the number of word (from the wordlist) to use in the passphrases.
.PARAMETER minwordlen
    An integer value for the minimum length of words used to assemble a passphrase.
.PARAMETER maxwordlen
    An integer value for the maximum length of words used to assemble a passphrase.
.PARAMETER casetrans
    A string value for the type of case transfrom to be used. Valid values are:
    	alternating:
    		Make the first word all caps, the second word all lowercase, third word all caps, etc.
    	capitalize:
    		Make the first letter of each word a capital letter, all others are lowercase.
    	lower:
    		Use only lowercase letters in passphrases.
    	random:
    		Use random capitalization for each letter in the passphrase.
    	upper:
    		Use only uppercase letters in passphrases.
    	as-is:
    		Use the word as it appears in your wordlist without any case transforms.
.PARAMETER sepchars
    A string value, simply an unseparted list of valid characters to use as word spearators (only one will be selected).
.PARAMETER paddigitspre
    An integer value of the number of digits to use at the front of the passphrase (after padding characters).
.PARAMETER paddigitspost
    An integer value of the number of digits to use at the end of the passphrase (befoer padding characters).
.PARAMETER padtype
    A string value for the type of padding to use. Valid values are:
    	adapt:
    		Use padding characters to meet the "padlength" value.
    	fixed:
    		Use a fixed number of padding characters to meet "padcharspre" and "padcharspost" values.
.PARAMETER padlength
    An integer value for the total number of characters used in any passphrase when padtype is set to adapt.
.PARAMETER padchars
    A string value, simply an unseparted list of valid characters to use as padding characters (only one will be selected).
.PARAMETER padcharspre
    A string value to represent the number of leading padding characters when padtype is set to fixed.
.PARAMETER padcharspost
    A string value to represent the number of ending padding characters when padtype is set to fixed.
.PARAMETER debug
    Enable debug output.
.PARAMETER showentropy
    Enable entropy calculation and display.
.PARAMETER help
    Show help message and exit.
.EXAMPLE
    C:\PS> xkcdpass.ps1
    ^Stylus'Unpack'Widget'83^
    =Nifty&Casino&Empty&88=
    @Harsh*Steam*Cheesy*16@

    The xkcdpass.ps1 script will by default use the STD profile with the .\xkcdpass.txt file as the dictionary.
    The standard profile (by default) will choose three words between five and eight characters, use a single
    padding character at the front and rear of the password, use a single character separator between words,
    add a two digit number to the end, and use CamelCase, as per above.
    the starting one.
.NOTES
    Author: DJ Lucas
    Date:   2024-05-13    
#>
param ( [String] $preset,
        [string] $dict,
        [int] $numpwds,
        [int] $numwords,
        [int] $minwordlen,
        [int] $maxwordlen,
        [string] $casetrans,
        [string] $sepchars,
        [int] $paddigitspre,
        [int] $paddgitspost,
        [string] $padtype,
        [int] $padlength,
        [string] $padchars,
        [int] $padcharspre,
        [int] $padcharspost,
        [switch] $showentropy = $False,
        [switch] $debug = $False,
        [switch] $help = $False)

$ENTROPY = @()
$DEFDICTIONARY = ".\xkcdpass.txt"
$DEFPRESET = "STD"

function Get-Preset-Params {
    param ( $Preset )
    if ($Preset -match "STD") {
        $global:num_words          = 3
        $global:word_len_min       = 4
        $global:word_len_max       = 6
        $global:case_trans         = "capitalize"
        $global:separators         = "@%^&*_+~?'/"
        $global:pad_digits_pre     = 0
        $global:pad_digits_post    = 2
        $global:padding_type       = "fixed"
        $global:pad_to_length      = 0
        $global:padding_chars      = "!@`$%^&=~?"
        $global:padding_chars_pre  = 1
        $global:padding_chars_post = 1
    }
    elseif ($Preset -match "WSE") {
        $global:num_words          = 2
        $global:word_len_min       = 5
        $global:word_len_max       = 6
        $global:case_trans         = "capitalize"
        $global:separators         = "!#`$^*-_=+"
        $global:pad_digits_pre     = 0
        $global:pad_digits_post    = 2
        $global:padding_type       = "adapt"
        $global:pad_to_length      = 16
        $global:padding_chars      = "!#`$^*=+"
        $global:padding_chars_pre  = 0
        $global:padding_chars_post = 0
    }
    elseif ($Preset -match "ALT") {
        $global:num_words          = 3
        $global:word_len_min       = 4
        $global:word_len_max       = 6
        $global:case_trans         = "capitalize"
        $global:separators         = ""
        $global:pad_digits_pre     = 2
        $global:pad_digits_post    = 0
        $global:padding_type       = "fixed"
        $global:pad_to_length      = 0
        $global:padding_chars      = "!@`$%^&*+=~?"
        $global:padding_chars_pre  = 0
        $global:padding_chars_post = 2
    }
    elseif ($Preset -match "STR") {
        $global:num_words          = 3
        $global:word_len_min       = 5
        $global:word_len_max       = 9
        $global:case_trans         = "capitalize"
        $global:separators         = "!@`$%^&*-_+=|~?"
        $global:pad_digits_pre     = 3
        $global:pad_digits_post    = 3
        $global:padding_type       = "fixed"
        $global:pad_to_length      = 0
        $global:padding_chars      = "!@`$%^&*_+=~?"
        $global:padding_chars_pre  = 2
        $global:padding_chars_post = 2
    }
}


function Get-Words {
param ($numwords,
       $minlen,
       $maxlen)
  $wordlist = @()
  foreach ($word in $global:dict.split()) {
    if ($word.length -ge $minlen -and $word.length -le $maxlen) {
      $wordlist += $word
    }
  }

  $count=1
  $mywords = @()
  while ( $count -le $numwords ){
    $index = Get-Random -Maximum ($wordlist.length - 1)
    $mywords += $wordlist[$index]
    $count++
  }
  return $mywords
}

function Get-CaseTrans {
  param ( [string]$transform,
          [string]$word,
          [int]$wordnum )
  if ($transform -eq "alternating") {
    $mod = $wordnum % 2
    if ($mod -eq 0) {
      $newword = $word.ToUpper()
    } else {
      $newword = $word.ToLower()
    }
  } elseif ($transform -eq "capitalize") {
    $newword = (Get-culture).TextInfo.ToTitleCase($word)
  } elseif ($transform -eq "upper") {
    $newword = $word.ToUpper()
  } elseif ($transform -eq "lower") {
    $newword = $word.ToLower()
  } elseif ($transform -eq "random") {
    $pcount = 0
    $newword = ""
    while ($pcount -lt $word.length) {
      $val = Get-Random -Maximum 1
      if ($val -eq 0) {
        $newword = $newword + $word[$pcount].ToUpper()
      } else {
        $newword = $newword + $word[$pcount].ToLower()
      }
      $pcount++
    }
  } elseif ($transform -eq "as-is") { 
    $newword += $word
  }
  return $newword
}

function Get-PadDigits {
  param ( $Length )
  $val = ""
  $count = 1
  while ( $count -le $Length) {
    $num = Get-Random -Maximum 9
    $val = $val + [string] $num
    $count++
  }
  return $val
}

function Get-Char {
  param ( $String )
  $val = Get-Random -Maximum $String.length
  return $String[$val]
}

# Go immediately into processing args
##### FIXME ##### Add input validation for string values
if ($help -eq $True) {
  get-help $PSCommandPath
  exit 0
}

if ($dict -eq "") {
  # Use EFF dice list if a dictionary is not provided
  $effwordlist = (Invoke-Webrequest https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
  $global:dict = $effwordlist.content -replace("[1-6][1-6][1-6][1-6][1-6]\t", '')
} else {
  if (!(Test-Path $dict)) {
    [Console]::Error.WriteLine("Error: '$dict' is not a valid path or does not exist!")
    exit 1
  }
  $global:dict = Get-content -Path $dict
}

if ($global:dict.length -lt 100) { 
  [Console]::Error.WriteLine("Error: Dictionary provided in unsuitable.")
  exit 2
}

# If we don't have internet access...maybe this could work rather than DEFDICTIONARY:
# Possible reasonable wordlist on windows 11
#$result = Get-content -Path 'C:\Windows\System32\VmFirmware Third-Party Notices.txt'
#$Array = @()
#foreach ($word in $result.split()) {
#  $wordnew = $word -replace '[.\/*-,`[]','' -replace ']', ''
#  if ($wordnew.length -gt 1 -and $wordnew.length -lt 12) {
#    $Array.Add($wordnew)
#  }
#}


if ($preset -eq "") {
  $global:preset = $DEFPRESET
} elseif ($preset -eq "STD" -or $preset -eq "WSE" -or $preset -eq "ALT" -or $preset -eq "STR") { 
  $global:preset = $preset
} else {
  [Console]::Error.WriteLine("Error: '$preset' is not a valid preset!")
  exit 1
}

Get-Preset-Params $preset

if ($numpwds -ne "") {
  $global:passcount = $numpwds
} else {
  $global:passcount = 3
}

if ($numwords -ne "") {
  $global:num_words
}

if ($minwordlen -ne "") {
  $global:word_len_min = $minwordlen
}

if ($maxwordlen -ne "") {
  $global:word_len_max = $maxwordlen
}

if ($casetrans -ne "") {
  $global:case_trans = $casetrans
}

if ($sepchars -ne "") {
  $global:separators = $sepchars
}

if ($paddigitspre -ne "") {
  $global:pad_digits_pre = $paddigitspre
}

if ($paddgitspost -ne "") {
  $global:pad_digits_post = $paddgitspost
}

if ($padtype -ne "") {
  $global:padding_type = $padtype
}

if ($padlength -ne "") {
  $global:padding_type = $padlength
}

if ($padchars -ne "") {
  $global:padding_chars = $padchars
}

if ($padcharspre -ne "") {
  $global:padding_chars_pre = $padcharspre
}

if ($padcharspost -ne "") {
  $global:padding_chars_pre = $padcharspost
}

if ($showentropy -eq $True) {
  $global:show_entropy = $True
} else {
  $global:show_entropy = $False
}

if ($debug -eq $True) {
  $global:show_debug = $True
} else {
  $global:show_debug = $False
}

if ($global:show_debug -eq $True ) {
  # Initial debug, print params
  echo "DEBUG: numpwds            : $global:passcount"
  echo "DEBUG: num_words          : $global:num_words"
  echo "DEBUG: word_len_min       : $global:word_len_min"
  echo "DEBUG: word_len_max       : $global:word_len_max"
  echo "DEBUG: case_trans         : $global:case_trans"
  echo "DEBUG: separators         : $global:separators"
  echo "DEBUG: pad_digits_pre     : $global:pad_digits_pre"
  echo "DEBUG: pad_digits_post    : $global:pad_digits_post"
  echo "DEBUG: padding_type       : $global:padding_type"
  echo "DEBUG: pad_to_length      : $global:pad_to_length"
  echo "DEBUG: padding_chars      : $global:padding_chars"
  echo "DEBUG: padding_chars_pre  : $global:padding_chars_pre"
  echo "DEBUG: padding_chars_post : $global:padding_chars_post"
  echo "DEBUG: preset             : $global:preset"
  echo "DEBUG: show_entropy       : $global:show_entropy"
  echo "DEBUG: show_debug         : $global:show_debug"
  echo ""
  echo ""
}

# DO SOME WORK NOW!
$wcount = 1
while ($wcount -le $global:passcount) {
  $myword = Get-Words $global:num_words $global:word_len_min $global:word_len_max
  $pcount = 0
  while ($pcount -lt $global:num_words) {
    $myword[$pcount] = Get-CaseTrans $global:case_trans $myword[$pcount] $pcount
    $pcount++
  }
  $mypadp = Get-PadDigits $global:pad_digits_pre
  $mypads = Get-PadDigits $global:pad_digits_post
  $mychar = Get-Char $global:padding_chars
  $mysep  = Get-Char $global:separators

  $PW = ""

  if ($global:padding_chars_pre -ne 0) {
    $pcount = 1
    while ( $pcount -le $global:padding_chars_pre ) {
      $PW = $PW + $mychar
      $pcount++
    }
  }

  if ($global:pad_digits_pre -ne 0) {
    $PW = $PW + $mypadp + $mysep
  }

  $pcount = 0
  while ( $pcount -le ($myword.length - 1)) {
    $PW= $PW + $myword[$pcount]
    $pcount ++
    if ($pcount -ne $myword.length) {
      $PW = $PW + $mysep
    }
  }

  if ($global:pad_digits_post -ne 0){
     $PW= $PW + $mysep + $mypads
  }
 
  if ($global:padding_chars_post -ne 0) {
    $pcount = 1
    while ( $pcount -le $global:padding_chars_post ) {
      $PW = $PW + $mychar
      $pcount++ 
    }
  }

  if ($global:pad_to_length -ne 0) {
    while ($PW.length -lt $global:pad_to_length ) {
      $PW = $PW + $mychar
    }
  }

  echo $PW
  $wcount++
}






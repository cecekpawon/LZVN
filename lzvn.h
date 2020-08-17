/*
 * Created..: 31 October 2014
 * Filename.: lzvn.c
 * Author...: Pike R. Alpha
 * Purpose..: Command line tool to LZVN encode/decode a file.
 *
 * Updates:
 *      - Prelinkedkerel check added (Pike R. Alpha, August 2015).
 *      - Mach header injection for prelinkedkernels added (Pike R. Alpha, August 2015).
 *      - Extract kernel option added (Pike R. Alpha, August 2015).
 *      - Extract dictionary option added (Pike R. Alpha, September 2015).
 *      - Extract kexts option added (Pike R. Alpha, September 2015).
 *      – Function find_load_command() added (Pike R. Alpha, September 2015).
 *      - Save Dictionary.plist in proper XML format.
 *      - Show number of signed and unsigned kexts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach/machine/boolean.h>

#include <architecture/byte_order.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFUnserialize.h>

#include "FastCompression.h"
#include "prelink.h"

/*
 * Copied from: kext_tools/kext_tools-326.95.1/kernelcache.h
 */

#define PLATFORM_NAME_LEN  (64)
#define ROOT_PATH_LEN     (256)

typedef struct prelinked_kernel_header
{
  uint32_t  signature;
  uint32_t  compressType;
  uint32_t  adler32;
  uint32_t  uncompressedSize;
  uint32_t  compressedSize;
  uint32_t  prelinkVersion;         // value >= 1 means KASLR supported
  uint32_t  reserved[10];
  char      platformName[PLATFORM_NAME_LEN];  // unused
  char      rootPath[ROOT_PATH_LEN];      // unused
  char      data[0];
} PrelinkedKernelHeader;

static u_int32_t gFileHeader[ 103 ] =
{
  0xBEBAFECA, 0x01000000, 0x07000001, 0x03000000, 0x1C000000, 0xFFFFFFFF, 0x00000000, 0x706D6F63,
  0x6E767A6C, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x01000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
};

/*==============================================================================
 * Copied from: kext_tools/kext_tools-326.95.1/kernelcache.c
 */

u_int32_t
local_adler32 (
  u_int8_t  *aBuffer,
  int32_t   aLength
  )
{
  int32_t     cnt;
  u_int32_t   result, lowHalf, highHalf;

  lowHalf   = 1;
  highHalf  = 0;

  for (cnt = 0; cnt < aLength; cnt++)
  {
    if ((cnt % 5000) == 0)
    {
      lowHalf  %= 65521L;
      highHalf %= 65521L;
    }

    lowHalf += aBuffer[cnt];
    highHalf += lowHalf;
  }

  lowHalf  %= 65521L;
  highHalf %= 65521L;

  result = (highHalf << 16) | lowHalf;

  return result;
}

/**************************************************************
 LZSS.C -- A Data Compression Program
***************************************************************
    4/6/1989 Haruhiko Okumura
    Use, distribute, and modify this program freely.
    Please send me your improved versions.
        PC-VAN      SCIENCE
        NIFTY-Serve PAF01022
        CompuServe  74050,1022

**************************************************************/
/*
 *  lzss.c - Package for decompressing lzss compressed objects
 *
 *  Copyright (c) 2003 Apple Computer, Inc.
 *
 *  DRI: Josh de Cesare
 */
#define N           (4096)  /* size of ring buffer - must be power of 2 */
#define F           (18)    /* upper limit for match_length */
#define THRESHOLD   (2)     /* encode string into position and length */

size_t
decompress_lzss (
  uint8_t   *aDst,
  size_t    aDstlen,
  uint8_t   *aSrc,
  size_t    aSrclen
  )
{
  /* ring buffer of size N, with extra F-1 bytes to aid string comparison */
  uint8_t         text_buf[N + F - 1];
  uint8_t         *dststart = aDst;
  const uint8_t   *dstend   = aDst + aDstlen;
  const uint8_t   *srcend   = aSrc + aSrclen;
  int             i, j, k, r, c;
  unsigned int    flags;

  aDst = dststart;
  for (i = 0; i < N - F; i++)
  {
    text_buf[i] = ' ';
  }

  r     = N - F;
  flags = 0;

  for ( ; ; ) {
    if (((flags >>= 1) & 0x100) == 0)
    {
      if (aSrc < srcend) c = *aSrc++; else break;
      flags = c | 0xFF00;  /* uses higher byte cleverly */
    }   /* to count eight */
    if (flags & 1)
    {
      if (aSrc < srcend) c = *aSrc++; else break;
      if (aDst < dstend) *aDst++ = c; else break;
      text_buf[r++] = c;
      r &= (N - 1);
    }
    else
    {
      if (aSrc < srcend) i = *aSrc++; else break;
      if (aSrc < srcend) j = *aSrc++; else break;
      i |= ((j & 0xF0) << 4);
      j  =  (j & 0x0F) + THRESHOLD;
      for (k = 0; k <= j; k++)
      {
        c = text_buf[(i + k) & (N - 1)];
        if (aDst < dstend) *aDst++ = c; else break;
        text_buf[r++] = c;
        r &= (N - 1);
      }
    }
  }

  return (size_t)(aDst - dststart);
}


//==============================================================================

struct load_command *
find_load_command (
  struct mach_header_64   *aMachHeader,
  uint32_t                aTargetCmd
  )
{
  struct load_command   *loadCommand;

  if (aMachHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return NULL;
  }

  // First LOAD_COMMAND begins after the mach header.
  loadCommand = (struct load_command *)((uint64_t)aMachHeader + sizeof (struct mach_header_64));

  while ((uint64_t)loadCommand < (uint64_t)aMachHeader + (uint64_t)aMachHeader->sizeofcmds + sizeof (struct mach_header_64))
  {
    if (loadCommand->cmd == aTargetCmd)
    {
      return (struct load_command *)loadCommand;
    }

    // Next load command.
    loadCommand = (struct load_command *)((uint64_t)loadCommand + (uint64_t)loadCommand->cmdsize);
  }

  // Return NULL on failure (not found).
  return NULL;
}


//==============================================================================

struct segment_command_64 *
find_segment_64 (
  struct mach_header_64   *aMachHeader,
  const char              *aSegmentName
  )
{
  struct load_command         *loadCommand;
  struct segment_command_64   *segment;

  if (aMachHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return NULL;
  }

  // First LOAD_COMMAND begins straight after the mach header.
  loadCommand = (struct load_command *)((uint64_t)aMachHeader + sizeof (struct mach_header_64));

  while ((uint64_t)loadCommand < (uint64_t)aMachHeader + (uint64_t)aMachHeader->sizeofcmds + sizeof (struct mach_header_64))
  {
    if (loadCommand->cmd == LC_SEGMENT_64)
    {
      // Check load command's segment name.
      segment = (struct segment_command_64 *)loadCommand;

      if (strcmp(segment->segname, aSegmentName) == 0)
      {
        return segment;
      }
    }

    // Next load command.
    loadCommand = (struct load_command *)((uint64_t)loadCommand + (uint64_t)loadCommand->cmdsize);
  }

  // Return NULL on failure (segment not found).
  return NULL;
}


//==============================================================================

uint8_t
is_prelinkedkernel (
  unsigned char   *aFileBuffer
  )
{
  struct segment_command_64   *prelinkTextSegment = NULL;
  struct segment_command_64   *prelinkInfoSegment = NULL;

  struct mach_header_64       *machHeader         = (struct mach_header_64 *)((unsigned char *)aFileBuffer);

  if (machHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return 0;
  }

  prelinkTextSegment = find_segment_64 (machHeader, "__PRELINK_TEXT");
  prelinkInfoSegment = find_segment_64 (machHeader, "__PRELINK_INFO");

  if ((prelinkInfoSegment && prelinkInfoSegment->filesize)
    && (prelinkTextSegment /*&& prelinkTextSegment->filesize*/)
    )
  {
    return 1;
  }

  return 0;
}


//==============================================================================

uint8_t
saveKernel (
  unsigned char   *aFileBuffer
  )
{
  struct segment_command_64   *textExecSegment    = NULL;
  struct segment_command_64   *lastSegment        = NULL;
  struct segment_command_64   *prelinkTextSegment = NULL;
  struct segment_command_64   *prelinkInfoSegment = NULL;
  struct segment_command_64   *linkeditSegment    = NULL;

  struct section_64           *prelinkTextSection = NULL;
  struct section_64           *prelinkInfoSection = NULL;

  struct mach_header_64       *machHeader         = (struct mach_header_64 *)((unsigned char *)aFileBuffer);

  if (machHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return -1;
  }

  if ((textExecSegment = find_segment_64 (machHeader, "__TEXT_EXEC")) != NULL)
  {
    machHeader = (struct mach_header_64 *)((unsigned char *)(aFileBuffer + textExecSegment->fileoff));

    if (machHeader->magic != MH_MAGIC_64) {
      printf ("ERROR: Invalid MachO header\n");
      return -1;
    }
  }

  if ((lastSegment = find_segment_64 (machHeader, "__LAST")) == NULL)
  {
    printf ("ERROR: find_segment_64 (\"__LAST\") failed\n");
    return -1;
  }

  if ((prelinkTextSegment = find_segment_64 (machHeader, "__PRELINK_TEXT")) == NULL)
  {
    printf ("ERROR: find_segment_64 (\"__PRELINK_TEXT\") failed\n");
    return -1;
  }

  if ((prelinkInfoSegment = find_segment_64 (machHeader, "__PRELINK_INFO")) == NULL)
  {
    printf ("ERROR: find_segment_64 (\"__PRELINK_INFO\") failed\n");
    return -1;
  }

  if ((linkeditSegment = find_segment_64 (machHeader, "__LINKEDIT")) == NULL)
  {
    printf ("ERROR: find_segment_64 (\"__LINKEDIT\") failed\n");
    return -1;
  }

  prelinkTextSegment->vmaddr    = linkeditSegment->vmaddr;
  prelinkTextSegment->vmsize    = 0;
  prelinkTextSegment->fileoff   = (lastSegment->fileoff + lastSegment->filesize);
  prelinkTextSegment->filesize  = 0;

  prelinkTextSection = (struct section_64 *)((uint64_t)prelinkTextSegment + sizeof (struct segment_command_64));

  prelinkTextSection->addr      = prelinkTextSegment->vmaddr;
  prelinkTextSection->size      = 0;
  prelinkTextSection->offset    = prelinkTextSegment->fileoff;

  prelinkInfoSegment->vmaddr    = linkeditSegment->vmaddr;
  prelinkInfoSegment->vmsize    = 0;
  prelinkInfoSegment->fileoff   = (lastSegment->fileoff + lastSegment->filesize);
  prelinkInfoSegment->filesize  = 0;

  prelinkInfoSection = (struct section_64 *)((uint64_t)prelinkInfoSegment + sizeof (struct segment_command_64));

  prelinkInfoSection->addr      = prelinkTextSegment->vmaddr;
  prelinkInfoSection->size      = 0;
  prelinkInfoSection->offset    = prelinkInfoSegment->fileoff;

  FILE *fp = fopen ("kernel", "wb");
  fwrite (aFileBuffer, 1, (long)(linkeditSegment->fileoff + linkeditSegment->filesize), fp);
  printf ("%ld bytes written\n", ftell (fp));
  fclose (fp);

  return 0;
}


//==============================================================================

uint8_t
saveDictionary (
  unsigned char   *aFileBuffer
  )
{
  struct segment_command_64   *prelinkInfoSegment = NULL;
  struct mach_header_64       *machHeader         = (struct mach_header_64 *)((unsigned char *)aFileBuffer);

  if (machHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return -1;
  }

  if ((prelinkInfoSegment = find_segment_64 (machHeader, "__PRELINK_INFO")) == NULL)
  {
    printf ("ERROR: find_segment_64 (\"__PRELINK_INFO\") failed\n");
    return -1;
  }

  const char  *prelinkInfoBytes = (const char *)aFileBuffer + prelinkInfoSegment->fileoff;

  CFPropertyListRef   prelinkInfoPlist = (CFPropertyListRef)IOCFUnserialize (prelinkInfoBytes, kCFAllocatorDefault, /* options */ 0, /* errorString */ NULL);

  if (prelinkInfoPlist)
  {
    printf ("NOTICE: Unserialized _PrelinkInfoDictionary\n");

    CFErrorRef  xmlError  = NULL;
    CFDataRef   xmlData   = CFPropertyListCreateData (kCFAllocatorDefault, prelinkInfoPlist, kCFPropertyListXMLFormat_v1_0, 0, &xmlError);

    if (xmlError == NULL)
    {
      const unsigned char *buffer   = CFDataGetBytePtr (xmlData);
      long                xmlLength = CFDataGetLength (xmlData);

      FILE *fp = fopen ("Dictionary.plist", "w");
      fwrite (buffer, 1, xmlLength, fp);
      printf ("%ld bytes written\n", ftell (fp));
      fclose (fp);
    }
  }

  return 0;
}


//==============================================================================

int
_mkdir (
  char    *aDirectory,
  mode_t  aMode
  )
{
  char        *p = aDirectory;

  struct stat sb;

  // Skip leading slashes.
  while (*p == '/')
  {
    p++;
  }

  while ((p = strchr (p, '/')))
  {
    *p = '\0';

    if (stat (aDirectory, &sb) != 0)
    {
      if (mkdir (aDirectory, aMode))
      {
        printf ("Error: cannot create directory: %s\n", aDirectory);
        return 1;
      }
    }

    // Restore slash.
    *p++ = '/';

    while (*p == '/')
    {
      p++;
    }
  }

  // Create the final directory component.
  if (stat (aDirectory, &sb) && mkdir (aDirectory, aMode))
  {
    printf ("Error: cannot create directory: %s", aDirectory);
    return 1;
  }

  return 0;
}


//==============================================================================

uint8_t
listKexts (
  unsigned char   *aFileBuffer,
  boolean_t       aSaveKexts
  )
{
  int signedKexts = 0;

  struct segment_command_64     *textExecSegment    = NULL;
  struct segment_command_64     *linkEditSegment    = NULL;
  struct segment_command_64     *prelinkTextSegment   = NULL;
  struct segment_command_64     *prelinkInfoSegment = NULL;
  struct mach_header_64         *machHeader         = (struct mach_header_64 *)((unsigned char *)aFileBuffer);
  struct linkedit_data_command  *codeSignature      = NULL;

  if (machHeader->magic != MH_MAGIC_64)
  {
    printf ("ERROR: Invalid MachO header\n");
    return -1;
  }

  uint32_t  delta = 0;

  textExecSegment    = find_segment_64 (machHeader, "__TEXT_EXEC");
  linkEditSegment    = find_segment_64 (machHeader, "__LINKEDIT");
  prelinkTextSegment = find_segment_64 (machHeader, "__PRELINK_TEXT");
  prelinkInfoSegment = find_segment_64 (machHeader, "__PRELINK_INFO");

  if (!linkEditSegment || !prelinkTextSegment || !prelinkInfoSegment)
  {
    printf ("ERROR: find_segment_64 (\"__LINKEDIT/__PRELINK_TEXT/__PRELINK_INFO\") failed\n");
    return -1;
  }

  uint32_t  base = (uint32_t)(linkEditSegment->vmaddr - linkEditSegment->fileoff);

  if (textExecSegment)
  {
    delta = textExecSegment->fileoff;

    machHeader = (struct mach_header_64 *)((unsigned char *)aFileBuffer + delta);
    if (machHeader->magic != MH_MAGIC_64)
    {
      printf ("ERROR: Invalid MachO header\n");
      return -1;
    }
  }

  //printf ("delta: %u\n", delta);
  //printf ("base: %u\n", base);

  printf ("prelinkInfoSegment->vmaddr..: 0x%llx\n", prelinkInfoSegment->vmaddr);
  printf ("prelinkInfoSegment->fileoff.: 0x%llx\n", prelinkInfoSegment->fileoff);
  printf ("prelinkInfoSegment->filesize: 0x%llx\n", prelinkInfoSegment->filesize);

  const char  *prelinkInfoBytes = (const char *)aFileBuffer + prelinkInfoSegment->fileoff;

  CFPropertyListRef   prelinkInfoPlist = (CFPropertyListRef)IOCFUnserialize (prelinkInfoBytes, kCFAllocatorDefault, /* options */ 0, /* errorString */ NULL);

  if (prelinkInfoPlist)
  {
    printf ("NOTICE: Unserialized prelink info\n");

    CFArrayRef  kextPlistArray  = (CFArrayRef)CFDictionaryGetValue (prelinkInfoPlist, CFSTR ("_PrelinkInfoDictionary"));
    CFIndex     i               = 0;
    CFIndex     kextCount       = CFArrayGetCount(kextPlistArray);

    printf ("kextCount: %ld\n", kextCount);

    char kextIdentifierBuffer[64];  // KMOD_MAX_NAME = 64
    char kextBundlePathBuffer[PATH_MAX];
    char kextPath[PATH_MAX];
    char kextPlistPath[PATH_MAX];
    char kextExecutablePath[PATH_MAX];

    struct stat st = {0};

    if (aSaveKexts)
    {
      if (kextCount && (stat ("kexts", &st) == -1))
      {
        mkdir ("kexts", 0755);
      }
    }

    for (i = 0; i < kextCount; i++)
    {
      // printf ("kextPlist: 0x%llx\n", (int64_t)kextPlist - (int64_t)fileBuffer - prelinkInfoSegment->fileoff);
      CFDictionaryRef   kextPlist = (CFDictionaryRef)CFArrayGetValueAtIndex (kextPlistArray, i);

      if (aSaveKexts)
      {
        CFStringRef   kextIdentifier = (CFStringRef)CFDictionaryGetValue (kextPlist, kCFBundleIdentifierKey);

        if (kextIdentifier)
        {
          CFStringGetCString (kextIdentifier, kextIdentifierBuffer, sizeof (kextIdentifierBuffer), kCFStringEncodingUTF8);
          printf ("\nCFBundleIdentifier[%3ld].......: %s\n", i, kextIdentifierBuffer);
        }
      }

      CFStringRef   bundlePath = (CFStringRef)CFDictionaryGetValue (kextPlist, CFSTR (kPrelinkBundlePathKey));

      if (bundlePath)
      {
        CFStringGetCString (bundlePath, kextBundlePathBuffer, sizeof (kextBundlePathBuffer), kCFStringEncodingUTF8);

        if (aSaveKexts)
        {
          printf ("_PrelinkBundlePath............: %s\n", kextBundlePathBuffer);

          sprintf (kextPath, "kexts%s", kextBundlePathBuffer);
          printf ("kextPath......................: %s\n", kextPath);

          if (stat (kextPath, &st) == -1)
          {
            printf ("_mkdir (%s, 755)\n", kextPath);
            _mkdir (kextPath, 0755);
          }
        }
        else
        {
          printf ("%s\n", kextBundlePathBuffer);
        }
      }

      if (aSaveKexts)
      {
        CFStringRef   executableRelativePath = (CFStringRef)CFDictionaryGetValue (kextPlist, CFSTR (kPrelinkExecutableRelativePathKey));

        if (executableRelativePath)
        {
          CFStringGetCString (executableRelativePath, kextBundlePathBuffer, sizeof (kextBundlePathBuffer), kCFStringEncodingUTF8);

          printf ("_PrelinkExecutableRelativePath: %s\n", kextBundlePathBuffer);

          if (strncmp (kextBundlePathBuffer, "Contents/MacOS/", 15) == 0)
          {
            sprintf (kextExecutablePath, "%s/Contents/MacOS", kextPath);
            printf ("kextExecutablePath............: %s\n", kextExecutablePath);

            if (stat (kextExecutablePath, &st) == -1)
            {
              _mkdir (kextExecutablePath, 0755);
              printf ("_mkdir (%s, 755)\n", kextExecutablePath);
            }
          }
          else
          {
            sprintf (kextExecutablePath, "%s", kextPath);
            printf ("kextExecutablePath............: %s\n", kextExecutablePath);
          }
        }
      }

      if (aSaveKexts)
      {
        CFStringRef executableName = (CFStringRef)CFDictionaryGetValue (kextPlist, kCFBundleExecutableKey);

        if (executableName)
        {
          uint64_t  offset          = 0;
          uint64_t  sourceAddress   = 0;
          uint64_t  sourceSize      = 0;

          CFStringGetCString (executableName, kextIdentifierBuffer, sizeof (kextIdentifierBuffer), kCFStringEncodingUTF8);
          printf ("CFBundleIdentifier............: %s\n", kextIdentifierBuffer);

          CFNumberRef kextSourceAddress = (CFNumberRef)CFDictionaryGetValue (kextPlist, CFSTR (kPrelinkExecutableSourceKey));

          if (kextSourceAddress)
          {
            CFNumberGetValue (kextSourceAddress, kCFNumberSInt64Type, &sourceAddress);
            offset = ((uint32_t)sourceAddress - base - delta);
            printf ("_PrelinkExecutableSourceAddr..: 0x%llx -> 0x%llx/%lld (offset)\n", sourceAddress, offset, offset);
          }

          CFNumberRef kextSourceSize = (CFNumberRef)CFDictionaryGetValue (kextPlist, CFSTR (kPrelinkExecutableSizeKey));

          if (kextSourceSize)
          {
            CFNumberGetValue (kextSourceSize, kCFNumberSInt64Type, &sourceSize);
            printf ("_PrelinkExecutableSize........: 0x%llx/%lld\n", sourceSize, sourceSize);
          }

          if (offset && sourceSize)
          {
            char            executablePath[PATH_MAX];
            unsigned char   *buff = (unsigned char *)(aFileBuffer + offset + delta);

            machHeader = (struct mach_header_64 *)buff;
            if (machHeader->magic != MH_MAGIC_64)
            {
              printf ("ERROR: Invalid MachO header\n");
              return -1;
            }
            codeSignature = (struct linkedit_data_command *)find_load_command (machHeader, LC_CODE_SIGNATURE);
            if (codeSignature)
            {
              printf ("Signed kext...................: Yes\n");
              signedKexts++;
            }

            sprintf (executablePath, "%s/%s", kextExecutablePath, kextIdentifierBuffer);
            printf ("executablePath................: %s\n", executablePath);

            FILE *executable = fopen (executablePath, "w");
            printf ("Magic ........................: %x\n", *(uint32_t *)machHeader);
            fwrite (machHeader, 1, sourceSize, executable);
            printf ("Executable....................: %s (%ld bytes written)\n", kextIdentifierBuffer, ftell (executable));
            fclose (executable);
          }
        }
      }

      if (aSaveKexts)
      {
        CFErrorRef  xmlError  = NULL;
        CFDataRef   xmlData   = CFPropertyListCreateData (kCFAllocatorDefault, kextPlist, kCFPropertyListXMLFormat_v1_0, 0, &xmlError);

        if (xmlError == NULL)
        {
          const unsigned char   *buffer   = CFDataGetBytePtr (xmlData);
          long                  xmlLength = CFDataGetLength (xmlData);

          sprintf (kextPlistPath, "%s/Info.plist", kextPath);
          printf ("kextPlistPath.................: %s\n", kextPlistPath);

          FILE *infoPlist = fopen (kextPlistPath, "w");
          fwrite (buffer, 1, xmlLength, infoPlist);
          printf ("Info.plist....................: %ld bytes written\n", ftell (infoPlist));
          fclose (infoPlist);
        }
        else
        {
          printf ("ERROR: Failed to convert/write Info.plist\n");
        }
      }
    }

    if (aSaveKexts)
    {
      printf ("\n%ld kexts extracted (%d signed and %ld unsigned)\n", kextCount, signedKexts, (kextCount - signedKexts));
    }
  }
  else
  {
    printf ("ERROR: Can't unserialize _PrelinkInfoDictionary\n");
    return -1;
  }

  return 0;
}

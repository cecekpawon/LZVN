/*
 * Created: 31 October 2014
 * Name...: lzvn.c
 * Author.: Pike R. Alpha
 * Purpose: Command line tool to LZVN encode/decode a prelinked kernel/file.
 *
 * Updates:
 *      - Support for lzvn_decode() added (Pike R. Alpha, November 2014).
 *      - Support for prelinkedkernels added (Pike R. Alpha, December 2014).
 *      - Debug output data added (Pike R. Alpha, July 2015).
 *      - Prelinkedkerel check added (Pike R. Alpha, August 2015).
 *      - Mach header injection for prelinkedkernels added (Pike R. Alpha, August 2015).
 *      - Extract kernel option added (Pike R. Alpha, August 2015).
 *      - Extract dictionary option added (Pike R. Alpha, September 2015).
 *      - Extract kexts option added (Pike R. Alpha, September 2015).
 *      – Function find_load_command() added (Pike R. Alpha, September 2015).
 *      - Save Dictionary.plist in proper XML format.
 *      - Show number of signed and unsigned kexts.
 *      - Usage now shows 'lzvn' once.
 *      - Show list of kexts added (Pike R. Alpha, Januari 2016).
 *      - Fixed encoding of files with a FAT header (Pike R. Alpha, July 2017).
 */

#include "lzvn.h"


//==============================================================================

void help ()
{
  printf ("Usage (encode): lzvn <infile> <outfile>\n");
  printf ("Usage (decode): lzvn -d <infile> [<outfile> | -kernel | -dictionary | -kexts | -list]\n");
}

int main (int argc, const char * argv[])
{
  FILE *fp  = NULL;

  unsigned char *fileBuffer        = NULL;
  unsigned char *workSpaceBuffer   = NULL;
  unsigned char *bufend            = NULL;
  unsigned char *buffer            = NULL;
  unsigned char *tmpFileBuffer     = NULL;

  PrelinkedKernelHeader * prelinkHeader = NULL;
  struct fat_header * fatHeader         = NULL;
  struct fat_arch   * fatArch           = NULL;

  unsigned int offset           = 0;

  unsigned long fileLength      = 0;
  unsigned long byteshandled    = 0;
  unsigned long file_adler32    = 0;
  unsigned long buffer_adler32  = 0;

  size_t compressedSize = 0;
  size_t workSpaceSize  = 0;

  int ret = -1;
  int i   = 0;

  int         optArgsCount  = 0;
  const char  *optInput     = NULL;
  const char  *optOuput     = NULL;
  boolean_t   optDecompress = FALSE;
  boolean_t   optCompress   = FALSE;
  boolean_t   optKernel     = FALSE;
  boolean_t   optDictionary = FALSE;
  boolean_t   optKexts      = FALSE;
  boolean_t   optList       = FALSE;

  for (int i = 1; i < argc; ++i)
  {
    switch (i)
    {
      case 1:
        if (!strcmp (argv[i], "-d"))
        {
          optDecompress = TRUE;
        }
        else
        {
          optCompress = TRUE;
          optInput    = argv[i];
        }

        optArgsCount++;
        break;

      case 2:
        if (optDecompress)
        {
          optInput = argv[i];
        }
        else if (optCompress)
        {
          optOuput = argv[i];
        }

        optArgsCount++;
        break;

      default:
        if (optDecompress)
        {
          if (!strcmp (argv[i], "-kernel"))
          {
            optKernel = TRUE;
          }
          else if (!strcmp (argv[i], "-dictionary"))
          {
            optDictionary = TRUE;
          }
          else if (!strcmp (argv[i], "-kexts"))
          {
            optKexts = TRUE;
          }
          else if (!strcmp (argv[i], "-list"))
          {
            optList = TRUE;
          }
          else {
            if (i == 3) {
              optOuput = argv[i];
            }
          }
        }

        optArgsCount++;
        break;
    }
  }

  /*
  printf ("optDecompress (%d)\n", optDecompress);
  printf ("optCompress (%d)\n", optCompress);
  printf ("optKernel (%d)\n", optKernel);
  printf ("optDictionary (%d)\n", optDictionary);
  printf ("optKexts (%d)\n", optKexts);
  printf ("optList (%d)\n", optList);
  printf ("optArgsCount (%d)\n", optArgsCount);

  printf ("optInput (%s)\n", optInput);
  printf ("optOuput (%s)\n", optOuput);
  */

  if ((!optDecompress && !optCompress)
    || (optInput == NULL)
    || (optDecompress && (optArgsCount <= 2))
    || (optCompress && (optArgsCount <= 1))
    )
  {
    help ();
    exit (ret);
  }

  //if (1) {
  //  exit (0);
  //}

  if (optDecompress)
  {
    fp = fopen (optInput, "rb");

    if (fp == NULL)
    {
      printf ("ERROR: Open file %s\n", optInput);
      exit (ret);
    }
    else
    {
      fseek (fp, 0, SEEK_END);

      fileLength = ftell (fp);
      if (fileLength <= 0)
      {
        printf ("ERROR: Empty file\n");
        fclose (fp);
        exit (ret);
      }

      printf ("Filesize: %ld bytes\n", fileLength);

      fseek (fp, 0, SEEK_SET);

      fileBuffer = malloc (fileLength);
      if (fileBuffer == NULL)
      {
        printf ("ERROR: Failed to allocate file buffer\n");
        fclose (fp);
        exit (ret);
      }
      else
      {
        boolean_t compressed = FALSE;

        fread (fileBuffer, fileLength, 1, fp);
        fclose (fp);

        // Check for a FAT header.
        fatHeader = (struct fat_header *)fileBuffer;

        if (fatHeader->magic == FAT_CIGAM)
        {
          unsigned int i = 1;

          fatArch       = (struct fat_arch *)(fileBuffer + sizeof (fatHeader));
          prelinkHeader = (PrelinkedKernelHeader *)(unsigned char *)(fileBuffer + OSSwapInt32 (fatArch->offset));

          while ((i < OSSwapInt32 (fatHeader->nfat_arch))
            && (prelinkHeader->signature != OSSwapInt32 ('comp'))
            )
          {
            printf ("Scanning ...\n");
            fatArch = (struct fat_arch *)(unsigned char *)(fatArch + sizeof (fatArch));
            prelinkHeader = (PrelinkedKernelHeader *)(fileBuffer + OSSwapInt32 (fatArch->offset));
            ++i;
          }

          // Is this a LZVN compressed file?
          if ((prelinkHeader->compressType == OSSwapInt32 ('lzvn'))
            || (prelinkHeader->compressType == OSSwapInt32 ('lzss'))
            )
          {
            printf ("Prelinkedkernel found\n");
          }
          else
          {
            printf ("ERROR: Unsupported compression format detected\n");
            ret = -1;
            goto doneUncompress;
          }
        }
        else
        {
          prelinkHeader = (PrelinkedKernelHeader *)(unsigned char *)fileBuffer;
        }

        if (prelinkHeader->signature == OSSwapInt32 ('comp'))
        {
          compressed = TRUE;
        }
        else
        {
          workSpaceBuffer = fileBuffer;
          workSpaceSize   = fileLength;
        }

        if (compressed)
        {
          if ((prelinkHeader->compressType == OSSwapInt32 ('lzvn'))
            || (prelinkHeader->compressType == OSSwapInt32 ('lzss'))
            )
          {
            workSpaceSize = OSSwapInt32 (prelinkHeader->uncompressedSize);
          }
          else
          {
            workSpaceSize = lzvn_encode_work_size ();
          }

          // printf ("workSpaceSize: %ld \n", workSpaceSize);

          if (workSpaceSize != 0)
          {
            workSpaceBuffer = malloc (workSpaceSize);
          }

          if (workSpaceBuffer == NULL)
          {
            printf ("ERROR: Failed to allocate workSpaceBuffer\n");
            ret = -1;
            goto doneUncompress;
          }
          else
          {
            tmpFileBuffer = (unsigned char *)prelinkHeader + sizeof (PrelinkedKernelHeader);

            fileLength = OSSwapInt32 (prelinkHeader->compressedSize);

            if (prelinkHeader->compressType == OSSwapInt32 ('lzss'))
            {
              compressedSize = decompress_lzss ((uint8_t *)workSpaceBuffer, workSpaceSize, (uint8_t *)tmpFileBuffer, fileLength);
            }
            else
            {
              compressedSize = lzvn_decode (workSpaceBuffer, workSpaceSize, tmpFileBuffer, fileLength);
            }

            if (compressedSize == 0)
            {
              printf ("ERROR: Decoding failed\n");
              ret = -1;
              goto doneUncompress;
            }
          }
        }

        // Are we unpacking a prelinkerkernel?
        if (is_prelinkedkernel (workSpaceBuffer))
        {
          printf ("Checking adler32 ... ");

          // Yes. Check adler32.
          if (compressed
            && (OSSwapInt32 (prelinkHeader->adler32) != local_adler32 (workSpaceBuffer, workSpaceSize))
            )
          {
            printf ("ERROR: Adler32 mismatch\n");
            ret = -1;
            goto doneUncompress;
          }
          else
          {
            printf ("OK (0x%08x)\n", OSSwapInt32 (prelinkHeader->adler32));

            if (optDictionary)
            {
              printf ("Extracting dictionary ...\n");
              saveDictionary (workSpaceBuffer);
            }

            if (optKexts)
            {
              printf ("Extracting kexts ...\n");
              listKexts (workSpaceBuffer, TRUE);
              optList = FALSE;
            }

            if (optList)
            {
              printf ("Getting list of kexts ...\n");
              listKexts (workSpaceBuffer, FALSE);
            }

            if (optKernel)
            {
              printf ("Extracting kernel ...\n");
              saveKernel (workSpaceBuffer);
            }

            if (compressed && (optOuput != NULL))
            {
              fp = fopen (optOuput, "wb");
              printf ("Decoding prelinkedkernel ...\nWriting data to: %s\n", optOuput);
              fwrite (workSpaceBuffer, 1, compressedSize, fp);
              printf ("%ld bytes written\n", ftell (fp));
              fclose (fp);
            }

            printf ("Done.\n");
            ret = 0;
            goto doneUncompress;
          }
        }

        printf ("ERROR: Unsupported format detected\n");
        ret = -1;

        doneUncompress:

        if (compressed && (workSpaceBuffer != NULL)) {
          free (workSpaceBuffer);
        }

        free (fileBuffer);
      }
    }
  }

  else if (optCompress)
  {
    fp = fopen (optInput, "rb");

    if (fp == NULL)
    {
      printf ("ERROR: Open file %s\n", optInput);
      exit (ret);
    }
    else
    {
      fseek (fp, 0, SEEK_END);

      fileLength = ftell (fp);
      if (fileLength <= 0) {
        printf ("ERROR: Empty file\n");
        fclose (fp);
        exit (ret);
      }

      printf ("fileLength...: %ld/0x%08lx - %s\n", fileLength, fileLength, optInput);

      fseek (fp, 0, SEEK_SET);

      fileBuffer = malloc (fileLength);
      if (fileBuffer == NULL)
      {
        printf ("ERROR: Failed to allocate file buffer\n");
        fclose (fp);
        exit (ret);
      }
      else
      {
        void * workSpace = NULL;

        fread(fileBuffer, fileLength, 1, fp);
        fclose (fp);

        size_t workSpaceSize = lzvn_encode_work_size();

        if (workSpaceSize != 0) {
          workSpace = malloc (workSpaceSize);
        }

        if (workSpace == NULL)
        {
          printf ("ERROR: Failed to allocate workspace\n");
          ret = -1;
          goto doneCompress;
        }
        else
        {
          printf ("workSpaceSize: %ld/0x%08lx\n", workSpaceSize, workSpaceSize);

          if (fileLength > workSpaceSize)
          {
            workSpaceSize = fileLength;
          }

          if (workSpaceSize != 0) {
            workSpaceBuffer = (void *)malloc (workSpaceSize);
          }

          if (workSpaceBuffer == NULL)
          {
            printf ("ERROR: Failed to allocate workSpaceBuffer\n");
            ret = -1;
            goto doneCompress;
          }
          else
          {
            // Check for a FAT header.
            fatHeader = (struct fat_header *)fileBuffer;

            if (fatHeader->magic == FAT_CIGAM)
            {
              fatArch = (struct fat_arch *)(fileBuffer + sizeof (fatHeader));
              offset = OSSwapInt32 (fatArch->offset);
            }

            tmpFileBuffer = (unsigned char *)fileBuffer + offset;

            if (is_prelinkedkernel (tmpFileBuffer))
            {
              file_adler32 = local_adler32 (tmpFileBuffer, fileLength);
              printf ("adler32......: 0x%08lx\n", file_adler32);

              size_t outSize = lzvn_encode (workSpaceBuffer, workSpaceSize, (u_int8_t *)tmpFileBuffer, (size_t)fileLength, workSpace);
              printf ("outSize......: %ld/0x%08lx\n", outSize, outSize);

              if ((outSize != 0) && (optOuput != NULL))
              {
                bufend          = workSpaceBuffer + outSize;
                compressedSize  = bufend - workSpaceBuffer;

                printf ("compressedSize.....: %ld/0x%08lx\n", compressedSize, compressedSize);

                fp = fopen (optOuput, "wb");

                printf ("Fixing file header for prelinkedkernel ...\n");

                // Inject arch offset into the header.
                gFileHeader[5]  = OSSwapInt32 (sizeof (gFileHeader) + outSize - 28);
                // Inject the value of file_adler32 into the header.
                gFileHeader[9]  = OSSwapInt32 (file_adler32);
                // Inject the uncompressed size into the header.
                gFileHeader[10] = OSSwapInt32 (fileLength);
                // Inject the compressed size into the header.
                gFileHeader[11] = OSSwapInt32 (compressedSize);

                printf ("Writing fixed up file header ...\n");

                fwrite (gFileHeader, (sizeof (gFileHeader) / sizeof (u_int32_t)), 4, fp);

                printf ("Writing workspace buffer ...\n");

                fwrite (workSpaceBuffer, outSize, 1, fp);
                fclose (fp);

                printf ("Done.\n");
                ret = 0;
                goto doneCompress;
              }

              printf ("ERROR: Encoding failed\n");
              ret = -1;
              goto doneCompress;
            }
          }
        }

        printf ("ERROR: Unsupported format detected\n");
        ret = -1;

        doneCompress:

        if (workSpace != NULL) {
          free (workSpace);
        }

        if (workSpaceBuffer != NULL) {
          free (workSpaceBuffer);
        }

        free (fileBuffer);
      }
    }
  }

  exit (ret);
}

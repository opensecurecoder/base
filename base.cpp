// Base converter (converts to any base) using 64 or 32 bit size registers. This means you don't need any Big integer library/code to simulate big integers. 
// Author Gor Nazaryan, Security Architect/Engineer/Consultant/Penetration Tester for over 20 years.
// Last Updated: 7/14/2018


/* Warranty
 * THIS SOFTWARE IS PROVIDED AS IS WITH NO WARRANTY. IN NO EVENT SHALL THE THIS PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION. 
 
 * License: GNU General Public License (GPL). You are granted to use this software freely. 
*/

#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
//#include <map>           // tree. fast but has order
#include <unordered_map>   // hash. This is must faster but no order
#include <string>
#include <iterator>
using namespace std;

#define BLOCKSIZE 8              // 8 bytes (use this for 64 bits) or 4 bytes (for 32 bits)
long FileSize(FILE*);
int TestBaseMaxEncodeSize();     // test
int TestBaseEncodeTruncSize();   // test

#if BLOCKSIZE == 8
  #define BLOCK_VAR unsigned long long
  #define BLOCK_PTR unsigned long long *
#else
  #define BLOCK_VAR unsigned long
  #define BLOCK_PTR unsigned long *
#endif    

// NOTE: The bcode must not contain any duplicate characters or else the index lookup will fail and wrong results will be decoded.
//const char bcode[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz#0,.<>;:{}[]|-!@$%^&*()+=~";    // for testing
//const char bcode[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";    // base 58
const char bcode[] = "123456789ABCDEFGHJKLMNPRSTUVWXYZabcdefghjknpqrstuvwxyz";        // base 54, Removed Q, m, o, i

//map<char,int> index;
unordered_map<char,int> index;

///////////////////////////////////////////////////////////////////////
// if error return -1 else return the max size of encode size.
// Only supports block size 4 and 8 bytes for 32 and 64 bit intergers.
///////////////////////////////////////////////////////////////////////
int GetBaseEncodeMaxSize(const int base, const int blockSize)
{
   int size = 0;        // max encode size

   if(blockSize != 4 && blockSize != 8)
       return -1;

   if(blockSize == 8)   // for 64 bit intergers
   {   
      if(base == 2)
          size = 64;   
      else if(base == 3)
          size = 41;
      else if(base == 4)
          size = 32;
      else if(base == 5)
          size = 28;
      else if(base == 6)
          size = 25;
      else if(base == 7)
          size = 23;
      else if(base == 8)
          size = 22;
      else if(base == 9)
          size = 21;
      else if(base == 10)
          size = 20;
      else if(base == 11)
          size = 19;
      else if(base == 12)
          size = 18;
      else if(base == 13)
          size = 18;
      else if(base == 14)
          size = 17;
      else if(base == 15)
          size = 17;
      else if(base > 15 && base < 20)
          size = 16;
      else if(base > 19 && base < 24)
          size = 15;
      else if(base > 23 && base < 31)
          size = 14;
      else if(base > 30 && base < 41)
          size = 13;
      else if(base > 40 && base < 57)
          size = 12;
      else if(base > 56 && base < 85)
           size = 11;
      else if(base > 84 && base < 129)
           size = 10;
      else size = -1;
    }
   else  // block size 4 for 32 bit integers 
   {
       if(base == 2)
          size = 32;
       else if(base == 3)
          size = 21;
       else if(base == 4)
          size = 16;
       else if(base == 5)
          size = 14;
       else if(base == 6)
          size = 13;
       else if(base == 7)
          size = 12;
       else if(base == 8)
          size = 11;
       else if(base == 9)
          size = 11;
       else if(base == 10)
          size = 10;
       else if(base == 11)
          size = 10;
       else if(base > 11 && base < 16)
          size = 9;
       else if(base > 15 && base < 24)
          size = 8;
       else if(base > 23 && base < 41)
          size = 7;
       else if(base > 40 && base < 85)
          size = 6;
       else if(base > 84 && base < 129)
          size = 5;
       else size = -1;

   }

   return size;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return the truncated size of last encoded block
/////////////////////////////////////////////////////////////////////////////////////////////////////////
int GetEncodedLastBlockTruncSize(int rawSize, int base, int maxEncodeSize)
{
    int trunc = 0;

    if(BLOCKSIZE == 8)
    {
       if(rawSize > 0 && rawSize < 8)
       {
          unsigned long long num = 1; 
          for(int i = 0; i < rawSize; i++)
              num *= 256;

          int i = 0;
          while(num >= base)
          {
                num /= base;
                i++;
          }
          i++;
          trunc = maxEncodeSize - i;
       }
    }
    else if(BLOCKSIZE == 4)
    {
       if(rawSize > 0 && rawSize < 4)
       {
          unsigned long num = 1; 
          for(int i = 0; i < rawSize; i++)
              num *= 256;

          int i = 0;
          while(num >= base)
          {
                num /= base;
                i++;
          }
          i++;
          trunc = maxEncodeSize - i;
       }
    }


/*
    if(BLOCKSIZE == 8)
    {
       if(base == 58)
       {
          if(rawSize == 7)
             trunc = maxEncodeSize - 10;
          else if(rawSize == 6)
             trunc = maxEncodeSize - 9;
          else if(rawSize == 5)
             trunc = maxEncodeSize - 7;
          else if(rawSize == 4)
             trunc = maxEncodeSize - 6;
          else if(rawSize == 3)
             trunc = maxEncodeSize - 5;
          else if(rawSize == 2)
             trunc = maxEncodeSize - 3;
          else if(rawSize == 1)
             trunc = maxEncodeSize - 2;
       }
    }
    else if(BLOCKSIZE == 4)
    {
         if(base == 58)
         {
            if(rawSize == 3)
               trunc = maxEncodeSize - 5;
            else if(rawSize == 2)
               trunc = maxEncodeSize - 3;
            else if(rawSize == 1)
               trunc = maxEncodeSize - 2;
         }
    }
    */

    return trunc;       
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return the truncated size of last decoded block
/////////////////////////////////////////////////////////////////////////////////////////////////////////
int GetDecodedLastBlockTruncSize(int encodeSize, int base, int maxEncodeSize)
{
    int trunc = 0;  

    if(BLOCKSIZE == 8)
    {
       if(encodeSize > 1 && encodeSize < 57)
       {
          unsigned long long num = base; 
          for(int i = 0; i < encodeSize-2; i++)
              num *= base;

          int i = 0;
          while(num)
          {
              num = num >> 8; // shift right 8 bits until we get zero. This will tell us how many bytes was used to get raw size
              i++;
          }

          trunc = BLOCKSIZE - i;
       }
    }
    else if(BLOCKSIZE == 4)
    {
       if(encodeSize > 1 && encodeSize < 25)
       {
          unsigned long num = base; 
          for(int i = 0; i < encodeSize-2; i++)
              num *= base;
         
          int i = 0;
          while(num)
          {
              num = num >> 8;
              i++;
          }
         
          trunc = BLOCKSIZE - i;
       }
    }

    /*

    if(BLOCKSIZE == 8)
    {
       if(maxEncodeSize == 11)
       {
          if(encodeSize == 10)
             trunc = BLOCKSIZE - 7;
          else if(encodeSize == 9)
             trunc = BLOCKSIZE - 6;
          else if(encodeSize == 7)
             trunc = BLOCKSIZE - 5;
          else if(encodeSize == 6)
             trunc = BLOCKSIZE - 4; 
          else if(encodeSize == 5)
             trunc = BLOCKSIZE - 3;
          else if(encodeSize == 3)
             trunc = BLOCKSIZE - 2;
          else if(encodeSize == 2)
             trunc = BLOCKSIZE - 1;
       }
    }
    else if(BLOCKSIZE == 4)
    {
       if(maxEncodeSize == 6)
       {         
          if(encodeSize == 5)
             trunc = BLOCKSIZE - 3;
          else if(encodeSize == 3)
             trunc = BLOCKSIZE - 2;
          else if(encodeSize == 2)
             trunc = BLOCKSIZE - 1;
       }
    }
    */

    return trunc;       
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
bool BaseEncode(unsigned char input[], const int inputSize, unsigned char output[], const int base, const int maxEncodeSize)
{
  int len = inputSize;  
  BLOCK_VAR block; 
  int x = 0;
  long mod = 0;
  bool pad = false;   // if true padding is needed
  unsigned char inputLastBlock[BLOCKSIZE] = {0};
  
  if(inputSize % BLOCKSIZE != 0) {
     len = (inputSize / BLOCKSIZE + 1) * BLOCKSIZE;
     pad = true;
  }
  
  for(int i = 0; i < len; i+=BLOCKSIZE)
  {
      if(pad == true && i == (len - BLOCKSIZE))
      {
         memcpy(inputLastBlock,input + (len-BLOCKSIZE),inputSize - (len-BLOCKSIZE));
         block = *((BLOCK_PTR)(inputLastBlock));
      }
      else
      {
         block = *((BLOCK_PTR)(input + i));
      }

      int c = 1;
      
      while(block >= base)
      {
          mod = block % base;
          block = block / base;       
          output[x] = bcode[mod];
          x++; c++;
      }
        
      output[x] = bcode[block];
      x++;

      if(maxEncodeSize != 0)       // if zero it's test
         for(; c < maxEncodeSize; c++)
         {
             output[x] = bcode[0];
             x++; 
         }      
  }

  return true;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
bool BaseDecode(unsigned char *input, const int inputSize, unsigned char output[], const int outputSize, const int base, const int maxEncodeSize)
{
    BLOCK_VAR total = 0;
    //map <char, int>::iterator iter;
    unordered_map <char, int>::iterator iter;
    //printf("\nFound:  key: %c   value: %d", iter->first, iter->second);         
    unsigned char ch = input[inputSize-1];
    int b = outputSize / BLOCKSIZE;
    iter = index.find(ch);
    int val = iter->second;
    total = val;     
           
    for(int i = inputSize-2; i >= 0; i--)
    {
       total *= base;
       ch = input[i];
       iter = index.find(ch);
       int val = iter->second;       
       total += val;              
              
       if(i % maxEncodeSize == 0 && i != 0)  
       {
          ((BLOCK_PTR)output)[b-1] = total;   
          unsigned char ch = input[i-1];
          iter = index.find(ch);
          int val = iter->second;
          total = val; 
          i--; b--;
       }
    }

    ((BLOCK_PTR)output)[0] = total;   // final block
    return true;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Main function ////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
int _tmain(int arg, _TCHAR* argv[])
{   
    //TestBaseEncodeTruncSize();
    //TestBaseMaxEncodeSize();
    //system("pause"); return 1;

    const int base = 58;
    int maxEncodeSize = GetBaseEncodeMaxSize(base,BLOCKSIZE);
    if(maxEncodeSize == -1)
       return false;

    if(base > strlen(bcode) || base < 2)
    {
        wprintf(L"Error. Base code size is incorrect.");
        return 1;
    }

    
    if(arg < 3 || (wcscmp(argv[2], L"e") != 0 && wcscmp(argv[2], L"d") != 0))
    {
        wprintf(L"\nUsage: base.exe <file> <option>\n e encode file\n d decode file");
        return 1;
    }   
    
    FILE *fs = _wfopen(argv[1], L"rb");   //open file for reading 

    if(fs == NULL)
    {
      wprintf(L"\nError opening file %s\n", argv[1]);
      return 1;
    }
       
    long datasize = FileSize(fs);
    if(datasize == 0)
    {
        wprintf(L"Can't process zero byte file.");
        return 1;
    }
   

    if(wcscmp(argv[2], L"e") == 0)  ////////////////// encode file
    {
      unsigned char *data = new unsigned char[datasize];

      if(data == NULL)
      {
         wprintf(L"\nError out of memory\n");
         return 1;
      }
  
      // copy the file into the buffer:
      size_t result = fread (data,1,datasize,fs);
      fclose(fs);

      if(result != datasize) 
      {
         wprintf(L"\nError reading file %s\n", argv[1]);
         delete [] data;
         return 1;
      }

      fs = _wfopen(L"data.enc", L"wb");   //open file for writting 

      if(fs == NULL)
      {
         wprintf(L"\nError writing file %s\n", L"data.enc");
         delete [] data;
         return 1;
      }
   
      int bufsize = datasize / BLOCKSIZE;
      int rem = datasize % BLOCKSIZE;
      int trunc = GetEncodedLastBlockTruncSize(rem,base,maxEncodeSize);
     
      if(rem != 0)
         bufsize++;   // lets add padding buffer

      if(bufsize == 0)
         bufsize = maxEncodeSize;
      else
         bufsize = bufsize * maxEncodeSize;

      int pad = 0;
      if(datasize % BLOCKSIZE != 0)
         pad = (datasize / BLOCKSIZE + 1) * BLOCKSIZE - datasize;
            
      unsigned char *buf = new unsigned char[bufsize];          // for input buffer to store the encoded data    
      BaseEncode(data,datasize,buf,base,maxEncodeSize);   
      fwrite(buf,1,bufsize-trunc,fs);
      fclose(fs);
      delete [] buf; delete [] data;
    }
    else  //////////////// decode file
    {
      int esize = datasize % maxEncodeSize;  // encoded last block size
      int trunc = GetDecodedLastBlockTruncSize(esize,base,maxEncodeSize);
      if(esize != 0)
         esize = maxEncodeSize - esize;    

      unsigned char *data = new unsigned char[datasize+esize];

      for(int i = 0; i < esize; i++)
          data[datasize+i] = bcode[0]; 

      if(data == NULL)
      {
         wprintf(L"\nError out of memory\n");
         return 1;
      }
  
      // copy the file into the buffer:
      size_t result = fread(data,1,datasize,fs);
      fclose(fs);

      if(result != datasize) 
      {
         wprintf(L"\nError reading file %s\n", argv[1]);
         delete [] data;
         return 1;
      }      
     
      fs = _wfopen(L"data.dec", L"wb");   //open file for reading 

      if(fs == NULL)
      {
         wprintf(L"\nError writing file %s\n", L"data.dec");
         delete [] data;
         return 1;
      }
   
      int bufsize = (datasize+esize) / maxEncodeSize * BLOCKSIZE;
      unsigned char *buf = new unsigned char[bufsize];         // for input buffer to store the decoded data    
  
      for(int i = 0; i < sizeof(bcode) - 1; i++)
          index.insert(pair <char, int> (bcode[i], i));     

      BaseDecode(data,datasize+esize,buf,bufsize,base,maxEncodeSize);     
      fwrite(buf,1,bufsize-trunc,fs);
      fclose(fs);
      delete [] buf; delete [] data;
    }
    
     
	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////
long FileSize(FILE *input)
{
   long fileSizeBytes;
   fseek(input, 0, SEEK_END);
   fileSizeBytes = ftell(input);
   fseek(input, 0, SEEK_SET);
   return fileSizeBytes;
}

/************************************************************************************************/
//////////////////////////////////////////////////////////////////////////////////////////////////
// Test  
//////////////////////////////////////////////////////////////////////////////////////////////////
/************************************************************************************************/
int TestBaseMaxEncodeSize()
{
   

     //-----------------------------------//
    // Used to get max base encoding  size
    //----------- Start TEST -----------------//
    
    #if BLOCKSIZE == 8
        unsigned char tdata[] =  "\xff\xff\xff\xff\xff\xff\xff\xff"; // for 64 bit use 8 bytes  data
    #else
        unsigned char tdata[] =  "\xff\xff\xff\xff"; // for 32 bit use 4 bytes data
    #endif
    
    unsigned char testbuf[256] = {0}; 
    printf("\nBase   Size");
    int tbase = 2;    // base to test

    for(; tbase <= 128; tbase++)
    {
         if(tbase > strlen(bcode) || tbase < 2)
         {
             printf("Error in testing. Base code size is incorrect.");
             break;
         }

        BaseEncode(tdata,sizeof(tdata)-1,testbuf,tbase,0);
        int size = strlen((char*)testbuf);      
        printf("\n%i    %i",tbase,size);
        memset(testbuf, 0, sizeof(testbuf));
    }

    //system("pause");
    return 0;
    
    
    //-------------- END TEST ---------------//



    /*
    const int base = 58;
    int maxEncodeSize = GetBaseEncodeMaxSize(base,BLOCKSIZE);
    if(maxEncodeSize == -1)
       return false;

    if(base > strlen(bcode) || base < 2)
    {
       printf("Error. Base code size is incorrect.");
       return 1;
    }

    unsigned char data[] =  "lkjwefRGERGihjfohfjefprwefwiojojergrehRETYJrhfEWGFYJeirjgoRTYRHe";  //"\xaf\xff\xde\xff\xfc\xdf\x78\x00\x01\xff\x10\x57\xcd\xa5\x78\xf5"; 
    int datasize = sizeof(data) - 1;
    int bufsize = datasize / BLOCKSIZE;

    if(datasize % BLOCKSIZE != 0)
       bufsize++;   // lets add padding buffer

    if(bufsize == 0)
       bufsize = maxEncodeSize;
    else
       bufsize = bufsize * maxEncodeSize;

    int pad = 0;
    if(datasize % BLOCKSIZE != 0)
       pad = (datasize / BLOCKSIZE + 1) * BLOCKSIZE - datasize;

    unsigned char *buf = new unsigned char[bufsize+1];          // for input buffer to store the encoded string
    unsigned char *buf2 = new unsigned char[datasize+pad+1];  // for output when decoded
    buf[bufsize] = 0;
    buf2[datasize] = 0;
  
    for(int i = 0; i < sizeof(bcode) - 1; i++)
        index.insert(pair <char, int> (bcode[i], i));     

    BaseEncode(data,datasize,buf,base,maxEncodeSize);
    printf("Base Encoded: %s", buf);
    int esize = strlen((char*)buf);   
    BaseDecode(buf,esize,buf2,datasize+pad,base,maxEncodeSize);
    printf("\nBase Decoded: %s\n\n", buf2);
    system("pause");
    delete [] buf; delete [] buf2;
	return 0;
    */
}
//////////////////////////////////////////////////////////////////////////////////////////////////
// Test  
//////////////////////////////////////////////////////////////////////////////////////////////////
int TestBaseEncodeTruncSize()
{    
    
    #if BLOCKSIZE == 8
        unsigned char tdata[] =  "\xff\xff\xff\xff\xff\xff\xff"; // for 64 bit use 8 bytes  data
    #else
        unsigned char tdata[] =  "\xff\xff\xff"; // for 32 bit use 4 bytes data
    #endif
    
    unsigned char testbuf[256] = {0}; 
    printf("\nBase   Raw Size   Encode Size");
    int tbase = 2;    // base to test

    for(; tbase <= 84; tbase++)
    {
         if(tbase > strlen(bcode) || tbase < 2)
         {
             printf("Error in testing. Base code size is incorrect.");
             break;
         }

        printf("\n------------------------------\nbase %i\n", tbase);

        int x = sizeof(tdata);
        for(int i = 1; i < x; x--)
        {
            BaseEncode(tdata,x-1,testbuf,tbase,0);
            int size = strlen((char*)testbuf);      
            printf("\n%i     %i              %i",tbase,x-1,size);
            memset(testbuf, 0, sizeof(testbuf));
        }

       
    }

    printf("\n\n");
   // system("pause");
    return 0;

}
---
layout: post
title: "HITCON CTF: baby_tcache Writeup"
date: 2018-10-25
excerpt: "Allocate chunk in stdout->_flags and partial overwrite _IO_write_base to get leak."
tags: [writeup, tcache, heap, filestructure]
category: [CTF_writeup, Exploitation]
description: Sample placeholder post.
---


**Attachments**: [binary](/assets/img/baby_tcache/baby_tcache)     [libc](/assets/img/baby_tcache/libc.so.6)     [exploit](/assets/img/baby_tcache/exploit.py)

This was a really fun challenge created by angelboy for HITCON CTF 2018. The following will be a writeup for the intended solution as gathered from the [exploit script](https://github.com/scwuaptx/CTF/blob/master/2018-writeup/hitcon/baby_tcache.py) that [angelboy](https://twitter.com/scwuaptx) uploaded.

**Note:** During the CTF we solved this challenge in a really impractical way (brute-forcing 12 bit's of libc address to get to `__free_hook` and `one_gadget`). The intended solution is really pretty cool as it involves getting a leak which looked impossible at the start.
{: .notice}

So, the binary that was provided was a stripped ELF 64 bit using libc version 2.27. The specialty of this version of libc is that, it implements the `tcache` concept that is used to cache free chunks in the heap before adding them to the libc freelist. Here are the mitigations enforced.

```javascript
  gdb-peda$ checksec
  CANARY    : ENABLED
  FORTIFY   : ENABLED
  NX        : ENABLED
  PIE       : ENABLED
  RELRO     : FULL
```

## Reversing

Reversing this binary is pretty easy. There are only 2 functionalities
  * **new_heap:** mallocs a chunk of user specified size and reads data into it. It then adds this chunk into a global array (lets call it `table`) and the size into another global array (say `size_arr`).
  * **delete_heap:** memsets `size` bytes of the chunk with the byte 0xda and then frees the chunk.

## Vulnerability

In the `new_heap` function, after reading `size` bytes of input from the user, chunk[size] is set to zero. This leads to a null-byte overflow in the `size` field of the next chunk if `size` corresponds to the exact size of the heap chunk.

```c
printf("Data:");
getinp(v6, size);
v6[size] = 0; // Null byte overflow
table[i] = v6;
v3 = size_array;
```

Thus we can use this to set the `PREV_IN_USE` bit of the next chunk to zero and achieve backward coalescing somewhat like what happens in House of Einherjar.

The main issue is that there is no way to get a leak. There is no convenient `view` functionality that we can use to get a leak. Thus we have to resort to partial overwrites, at least until we manage to get a leak (yes, though it seems stunning, we will get a leak :D)

## Exploit

Before actually starting off with pwning this binary, a quick note about `tcache`. This was a new feature introduced in glibc version 2.27 and above. Now all heap chunks of size < 0x410 are treated as tcache chunks. When these are freed, they go into their respective tcache bins (a singly linked list). Each bin can hold upto 7 chunks, after which chunks are freed as they were traditionally. So all chunks of size < 0x410 can be thought of as fastbin chunks. But the interesting part is that, unlike fastbin chunks tcache has **no** security checks in place. Thus we can double free pointers and malloc sizes without **any** size checks.

Getting back to this challenge, our plan can be to achieve a backward coalescing. But since we don't have any leaks, we will have to use a previously freed chunk as a target in our coalescing. So first, lets malloc a chunk of size > 0x410 so that we have unsorted bin pointer in the chunk. Assume we have a heap structure like this -

```
  chunk 0   # size = 0x500  => Target for backward coalescing of chunk 5. This will contain unsortedbin pointers
 ----------
  chunk 1   # size = 0x40   --+
 ----------                   |
  chunk 2   # size = 0x50     |==> Random tcache chunks
 ----------                   |
  chunk 3   # size = 0x60     |
 ----------                 --+
  chunk 4   # size = 0x70 => Use this for null byte overwrite of next size
 ----------
  chunk 5   # size = 0x500 => overwrite PREV_IN_USE of this chunk
 ----------
  chunk 6   # size = 0x80 => for preventing merge with topchunk
 ----------

```
For overwriting the `PREV_IN_USE` of chunk 5, free and reallocate chunk 4 with size 0x68 and set the `PREV_SIZE` so as to correspond with chunk 0 (PREV_SIZE = 0x660). After freeing chunk 5, chunk 0 will be a huge chunk with which we can overwrite the tcache chunks we created.

So how can we get arbitrary write from this? Well lets free chunk 2 and allocate 0x500+0x40=0x540 bytes. Thus we have unsorted bin pointer as `fd` of a tcache chunk. Now we allocate a chunk of any size, such that it gets serviced from the unsorted bin and overwrite the LSB of the unsorted bin pointer to point to some place we want within the libc. Note that the last three nibbles are constant, irrespective of ASLR. So to change the last 2 bytes, we have to use 4 bit bruteforce.

Now our aim is to get a leak. We'll take a diversion now and start looking into the internals of `puts`.

`puts` internally calls `_IO_new_file_xsputn` which eventually calls `_IO_OVERFLOW`

```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      :
      :
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,  // our target
			 f->_IO_write_ptr - f->_IO_write_base);
```
We see that `_IO_do_write` is called eventually in this function. For this `stdout->_flags & _IO_NO_WRITES` should be zero. Also we set `stdout->_flags & _IO_CURRENTLY_PUTTING` to avoid some unnecessary (in our case) code.

`_IO_new_file_overflow` calls `_IO_do_write` with arguments as `stdout`, `stdout->_IO_write_base` and size of the buffer.

`_IO_do_write` calls `new_do_write` with same arguments.

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do); // Our aim
  :
  :
```
`_IO_SYSWRITE` is basically `write(fp->fileno, data, to_do)` which is what we want. Also `_IO_SYSSEEK` is basically just a call to `lseek` on the given file with the given arguments. The issue is that we don't exactly control `fp->_IO_write_base - fp->_IO_read_end`. If we set `stdout->_IO_read_end` to zero, then the second argument is too long, and is we set `stdout->_IO_write_base` > `stdout->_IO_read_end` we'll have issues elsewhere, owing to `_IO_write_base` becomming greater than `_IO_write_ptr`. Thus our only option is to skip the `else if` block. For this we have to set `stdout->_flags & _IO_IS_APPENDING`

Therefore to get to `_IO_SYSWRITE`, we need to set the flags in the following manner
```c
_flags = 0xfbad0000  // Magic number
_flags & = ~_IO_NO_WRITES // _flags = 0xfbad0000
_flags | = _IO_CURRENTLY_PUTTING // _flags = 0xfbad0800
_flags | = _IO_IS_APPENDING // _flags = 0xfbad1800
 ```

 By the way did you notice the second argument of `_IO_do_write`? It's `_IO_write_base` which is eventually the second argument for `write`. Thus we can leak data from `stdout->_IO_write_base`!

 Now all we have to do is to set `stdout->_flags` to the value we calculated and partial overwrite `stdout->_IO_write_base` so as to point it to somewhere to get a leak.

 So we overwrite the `fd` of our free tcache chunk to point to `stdout->_flags`. Here we will hardcode the last 2 bytes. The last 3 nibbles are constant anyway so we only need to bruteforce the fourth last nibble (4-bit bruteforce). Now we allocate a junk chunk and then chunk after that will lie in our desired region. Keep in mind that there are no size checks here, so the lack of the chunk size in the target location does not cause an issue.

 We overwrite `_flags` with the calculated value and `_IO_read_ptr`, `_IO_read_end`, `_IO_read_base` with NULL and the last byte of `_IO_write_base` with NULL as well.

 Heres how `stdout` looked after the overwrite
```
gdb-peda$ x/28xg 0x00007ffff7dd0760
0x7ffff7dd0760 <_IO_2_1_stdout_>:       0x00000000fbad1800      0x0000000000000000
0x7ffff7dd0770 <_IO_2_1_stdout_+16>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd0780 <_IO_2_1_stdout_+32>:    0x00007ffff7dd0700      0x00007ffff7dd07e3
0x7ffff7dd0790 <_IO_2_1_stdout_+48>:    0x00007ffff7dd07e3      0x00007ffff7dd07e3
0x7ffff7dd07a0 <_IO_2_1_stdout_+64>:    0x00007ffff7dd07e4      0x0000000000000000
0x7ffff7dd07b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd07c0 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7dcfa00
0x7ffff7dd07d0 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7ffff7dd07e0 <_IO_2_1_stdout_+128>:   0x000000000a000000      0x00007ffff7dd18c0
0x7ffff7dd07f0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7dd0800 <_IO_2_1_stdout_+160>:   0x00007ffff7dcf8c0      0x0000000000000000
0x7ffff7dd0810 <_IO_2_1_stdout_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd0820 <_IO_2_1_stdout_+192>:   0x00000000ffffffff      0x0000000000000000
0x7ffff7dd0830 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7dcc2a0
```
In the above structure, `_IO_write_base` = `0x00007ffff7dd0700` and `_IO_write_ptr` = `0x00007ffff7dd07e3`. So we'll leak lot of memory in which we are sure to get a libc leak :).

Once we get the libc leak, exploitation is trivial. We just free another tcache chunk and overwrite its `fd` with a pointer to `__free_hook`. Then after 1 allocation of chunks in that tcache bin, we get a allocation at `__free_hook` and overwrite that with a [one_gadget](https://github.com/david942j/one_gadget).

After this we just call `free` with the `delete_heap` functionality to get shell!

We'll have to run the exploit several times until our bruteforce pays off.

The flag was

    hitcon{He4p_ch41leng3s_4r3_n3v3r_d34d_XD}

My team (bi0s) stood 26 in this CTF. We had an awesome time trying out the challenges. Shout out to the HITCON team for organizing this CTF!

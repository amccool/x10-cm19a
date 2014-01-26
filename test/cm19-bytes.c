/* 
 * Little Sample/Test program to read data from the CM19a using the
 * x10-cm19a-0.0.6b kernel driver by Michael LeMay
 * 
 * 2006 Ruud Linders
 * No rights reserved !
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

main()
{
   int fh;
   char turnOn;
   char house;
   int num,res;
   char buf[10];
   
/* Note that non_blocking read =does= work but not as reliable
 * fh=open("/dev/cm19a0", O_RDWR | O_NONBLOCK); */
   fh=open("/dev/cm19a0", O_RDWR);

   if (fh < 0) 
     {
	fprintf(stderr,"open failed\n");
	exit(1);
     }
   
   printf("opened\n");
   
   while (1)
     {
	res= read(fh, buf, 5);
	buf[5]= '\0';
	fprintf(stderr, "read %d bytes\n", res);
	if (res == 5)
	  {
	     sscanf(buf, "%c%c%02d\n", &turnOn, &house, &num);
	     printf("onoff %c, house %c, num %d\n", turnOn, house,num);
	  }
	
	sleep(3); 
     }
   
  close(fh);
}

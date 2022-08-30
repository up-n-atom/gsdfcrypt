# F@st 5566/~~5689~~ configuration restoration tool

Decodes and encodes backup *cfg* files.

### Usage:

&emsp;gsdfcrypt [-c] [-k 128|256] [-p password] &lt;in&gt; &lt;out&gt;

&emsp;**-c**
  
&emsp;&emsp;Compress/Create encoded configuration
  
&emsp;**-k 128 | 256**

&emsp;&emsp;Secret-key size.
  
&emsp;&emsp;F@st 5566 = 128
  
&emsp;&emsp;F@st 5689 = 256 (default)

&emsp;**-p**

&emsp;&emsp;F@st 5566/5689 user password



### Example:

&emsp;[Enable root/admin SSH on the F@st 5566](https://github.com/up-n-atom/gsdfcrypt/wiki/F@st-5566-SSH)

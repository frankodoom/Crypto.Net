using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Cryptography
{
    class Program
    {
        static void Main(string[] args)
        {

            //https://www.codeproject.com/articles/704865/salted-password-hashing-doing-it-right
            Console.WriteLine("Cryptographic Hash Password With Salt Based on OBVTEX ");
            Console.WriteLine("© 2017- Compiled By Frank Odoom");
            Console.WriteLine("Enter Your Password");
            string password =Console.ReadLine();
            string output=Hasher.ComputeHash(password, "SHA256", null);
            Console.WriteLine("The Salt & Hashed Password is " + " " + output);
            Console.ReadLine();

        }

    }
}

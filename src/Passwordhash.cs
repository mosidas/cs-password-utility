using System.Security.Cryptography;

namespace password_utility
{
    public class Passwordhash
    {
        public static byte[] MakeSalt(int length)
        {
            return RandomNumberGenerator.GetBytes(length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="passsword"></param>
        /// <param name="salt">should be salt.length >= 8</param>
        /// <returns></returns>
        public static string MakePasswordHash(string passsword, byte[] salt)
        {
            using var rfc2898DeriveBytes = new Rfc2898DeriveBytes(passsword, salt, 10000, HashAlgorithmName.SHA256);
            byte[] hash = rfc2898DeriveBytes.GetBytes(32);
            return Convert.ToBase64String(hash);
        }
    }
}

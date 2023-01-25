using System.Security.Cryptography;

namespace password_utility
{
    public class OneTimePassword
    {
        public static byte[] MakeSecretKey(int length)
        {
            return RandomNumberGenerator.GetBytes(length);
        }

        /// <summary>
        /// HMAC-based One-Time Password 
        /// </summary>
        /// <param name="secretKey">secret key</param>
        /// <param name="counter">counter</param>
        /// <returns>One-Time Password</returns>
        public static string GenerateHOTP(byte[] secretKey, long counter)
        {
            var K = secretKey;
            var C = BitConverter.GetBytes(counter);
            // convert to big endian.
            Array.Reverse(C);

            // HOTP(K,C)
            // Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
            using var hmacsha1 = new HMACSHA1(K);
            var HS = hmacsha1.ComputeHash(C);

            // Step 2: Generate a 4-byte string (Dynamic Truncation)
            // Step 3: Compute an HOTP value
            // → Example of HOTP Computation for Digit = 6
            var offset = HS[HS.Length - 1] & 0xf;
            var code = ((HS[offset] & 0x7f) << 24)
              | ((HS[offset + 1] & 0xff) << 16)
              | ((HS[offset + 2] & 0xff) << 8)
              | ((HS[offset + 3] & 0xff));

            // 6桁取り出す。
            return (code % 1000000).ToString("000000");
        }

        /// <summary>
        /// Time-based One-Time Password(rfc6238)
        /// Keys SHOULD be of the length of the HMAC output(20) to facilitate interoperability.
        /// </summary>
        /// <param name="secretKey">secert key</param>
        /// <param name="lifeTime">life time</param>
        /// <remarks>
        /// test: https://rootprojects.org/authenticator/
        /// </remarks>
        /// <returns>One-Time Password</returns>
        public static string GenerateTOTP(byte[] secretKey, int lifeTime)
        {
            var epochSeconds = GetEpochSeconds();
            var counter = epochSeconds / lifeTime;
            return GenerateHOTP(secretKey, counter);
        }

        /// <summary>
        /// EpochSeconds.
        /// </summary>
        /// <returns>Epoch seconds</returns>
        private static long GetEpochSeconds()
        {
            var span = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (long)span.TotalSeconds;
        }
    }
}

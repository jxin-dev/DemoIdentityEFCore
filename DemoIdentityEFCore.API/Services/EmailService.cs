using System.Net.Mail;
using System.Net;

namespace DemoIdentityEFCore.API.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(string emailTo, string subject, string body);
    }
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string emailTo, string subject, string body)
        {
            string MailServer = _configuration["EmailSettings:MailServer"] ?? throw new ArgumentNullException(nameof(MailServer));
            string Username = _configuration["EmailSettings:Username"] ?? throw new ArgumentNullException(nameof(Username));
            string Password = _configuration["EmailSettings:Password"] ?? throw new ArgumentNullException(nameof(Password));
            int Port = !string.IsNullOrWhiteSpace(_configuration["EmailSettings:Port"]) ? int.Parse(_configuration["EmailSettings:Port"]!) : throw new ArgumentNullException(nameof(Port));
            string FromEmail = _configuration["EmailSettings:FromEmail"] ?? throw new ArgumentNullException(nameof(FromEmail));
            string DisplayName = _configuration["EmailSettings:DisplayName"] ?? throw new ArgumentNullException(nameof(DisplayName));


            using var client = new SmtpClient(MailServer, Port)
            {
                Credentials = new NetworkCredential(Username, Password),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(Username, $"{DisplayName} <{FromEmail}>"),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            mailMessage.To.Add(emailTo);

            await client.SendMailAsync(mailMessage);
        }


    }
}

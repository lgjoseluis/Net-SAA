using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Newtonsoft.Json.Linq;

namespace UsersApplication.Services
{
    public class MailJetSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly MailJetOptions _mailJetOptions;

        public MailJetSender(IConfiguration configuration)
        {
            _configuration = configuration;
            _mailJetOptions = _configuration.GetSection("MailJet").Get<MailJetOptions>();
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            MailjetClient client = new MailjetClient(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey);
            MailjetRequest request = new MailjetRequest
            {
                Resource = Send.Resource,
            }
            .Property(Send.FromEmail, "lgjoseluis@proton.me")
            .Property(Send.FromName, "José Luis")
            .Property(Send.Subject, subject)
            //.Property(Send.TextPart, "Welcome to Mailjet! May the delivery force be with you!")
            .Property(Send.HtmlPart, htmlMessage)
            .Property(Send.Recipients, new JArray 
            {
                new JObject 
                {
                    {"Email", email}
                }
             });

            MailjetResponse response = await client.PostAsync(request);

            if (response.IsSuccessStatusCode)
            {
                //log info
                string str = $"Total: { response.GetTotal() }, Count: {response.GetCount() }";                
            }
            else
            {
                //log error
                string str = $"StausCode: {response.StatusCode}, ErrorInfo: {response.GetErrorInfo()}, ErrorMessage: {response.GetErrorMessage() }";                
            }
            
        }
    }
}

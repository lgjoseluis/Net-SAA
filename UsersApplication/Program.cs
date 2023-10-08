using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using UsersApplication.Data;
using UsersApplication.Services;

var builder = WebApplication.CreateBuilder(args);

//Configure DB connection
builder.Services.AddDbContext<ApplicationDbContext>(
        options => options.UseSqlServer(
                builder.Configuration.GetConnectionString("SQL_CONNECTION")
            )
    );

//Add identity service
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

//Set url return 
builder.Services.ConfigureApplicationCookie(options => { 
    options.LoginPath = new PathString("/AccountUsers/Login");
    options.AccessDeniedPath = new PathString("/AccountUsers/UserBlocked");
});

//Configure identity options
builder.Services.Configure<IdentityOptions>( options => { 
    options.Password.RequiredLength = 6;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

//IEmailSender
builder.Services.AddTransient<IEmailSender, MailJetSender>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//Add authentication
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

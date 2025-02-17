package com.weare5stones.keycloak.authenticators.emailotp;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.*;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.beans.ProfileBean;
import org.keycloak.forms.login.freemarker.model.UrlBean;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.FreeMarkerException;
import org.keycloak.theme.Theme;
import org.keycloak.theme.beans.MessageFormatterMethod;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.keycloak.utils.EmailValidationUtil;

public class EmailOTPAuthenticator implements Authenticator {

  private static final String TOTP_FORM = "totp-form.ftl";
  private static final String TOTP_EMAIL = "totp-email.ftl";
  private static final String TOTP_SMS = "totp-sms.ftl";
  private static final String AUTH_NOTE_CODE = "code";
  private static final String AUTH_NOTE_TTL = "ttl";
  private static final String AUTH_NOTE_REMAINING_RETRIES = "remainingRetries";
  private static final Logger logger = Logger.getLogger(EmailOTPAuthenticator.class);

  private static final String ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String NUM = "0123456789";

  protected FreeMarkerProvider freeMarker;

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    KeycloakSession session = context.getSession();
    UserModel user = context.getUser();

    int ttl = Integer.parseInt(config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL));
    String emailSubject = config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_EMAIL_SUBJECT);
    String emailAttribute = config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAIL_ATTR);
    Boolean isSimulation = Boolean.parseBoolean(
        config.getConfig()
            .getOrDefault(
                EmailOTPAuthenticatorFactory.CONFIG_PROP_SIMULATION,
                "false"));
    Boolean SMSTemplate = Boolean.parseBoolean(
      config.getConfig()
        .getOrDefault(
          EmailOTPAuthenticatorFactory.CONFIG_PROP_SMSTEMPLATE,
          "false"));
    String code = getCode(config);
    int maxRetries = getMaxRetries(config);
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    authSession.setAuthNote(AUTH_NOTE_CODE, code);
    authSession.setAuthNote(AUTH_NOTE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
    authSession.setAuthNote(AUTH_NOTE_REMAINING_RETRIES, Integer.toString(maxRetries));

    try {
      RealmModel realm = context.getRealm();

      if (isSimulation) {
        logger.warn(String.format(
            "***** SIMULATION MODE ***** Would send a TOTP email to %s with code: %s",
            user.getEmail(),
            code));
      } else {
        String realmName = Strings.isNullOrEmpty(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();
        List<Object> subjAttr = ImmutableList.of(realmName);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);
        attributes.put("ttl", Math.floorDiv(ttl, 60));

        if (user.getFirstAttribute(emailAttribute) == null) {
          throw new Exception("The user has not " + emailAttribute + ".");
        }
        String email = user.getFirstAttribute(emailAttribute);
        if (EmailValidationUtil.isValidEmail(email) == false){
          throw new Exception("The user has not valid email address in " + emailAttribute + ".");
        }
        EmailTemplate emailTemplate = null;
        if (SMSTemplate) {
          //SMS template-et kell használni, htmlbody-t nem küldünk
          emailTemplate = processTemplate(emailSubject, subjAttr, TOTP_SMS, attributes, session, user,realm);
          sendEmail(session, user, email, emailTemplate.getSubject(), emailTemplate.getTextBody(), null);
        }else {
          //email template használat
          emailTemplate = processTemplate(emailSubject, subjAttr, TOTP_EMAIL, attributes, session, user,realm);
          sendEmail(session, user, email, emailTemplate.getSubject(), emailTemplate.getTextBody(), emailTemplate.getHtmlBody());
        }
      }
      Map<String, Object> formAttributes = new HashMap<>();
      formAttributes.put("realm", context.getRealm());
      if (isSimulation){
        formAttributes.put("code", code);
      }
      context.challenge(context.form().setAttribute("attributes", formAttributes).createForm(TOTP_FORM));
    } catch (Exception e) {
      logger.error("An error occurred when attempting to email an TOTP auth:", e);
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().setError("emailTOTPEmailNotSent", e.getMessage())
              .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
    }
  }

  private void sendEmail(KeycloakSession session, UserModel user, String email, String subject,  String textBody, String htmlBody) {
    try {
      EmailSenderProvider emailProvider = session.getProvider(EmailSenderProvider.class);

      RealmModel realm = session.getContext().getRealm();
      Map<String, String> smtpConfig = realm.getSmtpConfig();
      //
      emailProvider.send(smtpConfig, email, subject, textBody, htmlBody);
    } catch (EmailException e) {
      logger.error("An error occurred when attempting to email an TOTP auth:", e);
    }
  }

  protected Theme getTheme(KeycloakSession session) throws IOException {
    return session.theme().getTheme(Theme.Type.EMAIL);
  }
  protected EmailTemplate processTemplate(String subjectKey, List<Object> subjectAttributes, String template, Map<String, Object> attributes, KeycloakSession session, UserModel user, RealmModel realm) throws EmailException {
    try {
      Theme theme = getTheme(session);
      Locale locale = session.getContext().resolveLocale(user, theme.getType());
      this.freeMarker = session.getProvider(FreeMarkerProvider.class);
      attributes.put("locale", locale);

      Properties messages = theme.getEnhancedMessages(realm, locale);
      attributes.put("msg", new MessageFormatterMethod(locale, messages));

      attributes.put("properties", theme.getProperties());
      attributes.put("realmName", realm.getDisplayName());
      attributes.put("user", new ProfileBean(user, session));
      KeycloakUriInfo uriInfo = session.getContext().getUri();
      attributes.put("url", new UrlBean(realm, theme, uriInfo.getBaseUri(), null));

      String subject = new MessageFormat(messages.getProperty(subjectKey, subjectKey), locale).format(subjectAttributes.toArray());
      String textTemplate = String.format("text/%s", template);
      String textBody;
      try {
        textBody = freeMarker.processTemplate(attributes, textTemplate, theme);
      } catch (final FreeMarkerException e) {
        throw new EmailException("Failed to template plain text email.", e);
      }
      String htmlTemplate = String.format("html/%s", template);
      String htmlBody;
      try {
        htmlBody = freeMarker.processTemplate(attributes, htmlTemplate, theme);
      } catch (final FreeMarkerException e) {
        throw new EmailException("Failed to template html email.", e);
      }

      return new EmailTemplate(subject, textBody, htmlBody);
    } catch (Exception e) {
      throw new EmailException("Failed to template email", e);
    }
  }

  protected static class EmailTemplate {

    private String subject;
    private String textBody;
    private String htmlBody;

    public EmailTemplate(String subject, String textBody, String htmlBody) {
      this.subject = subject;
      this.textBody = textBody;
      this.htmlBody = htmlBody;
    }

    public String getSubject() {
      return subject;
    }

    public String getTextBody() {
      return textBody;
    }

    public String getHtmlBody() {
      return htmlBody;
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String code = authSession.getAuthNote(AUTH_NOTE_CODE);
    String ttl = authSession.getAuthNote(AUTH_NOTE_TTL);
    String remainingAttemptsStr = authSession.getAuthNote(AUTH_NOTE_REMAINING_RETRIES);
    int remainingAttempts = remainingAttemptsStr == null ? 0 : Integer.parseInt(remainingAttemptsStr);

    if (code == null || ttl == null) {
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
      return;
    }

    boolean isValid = enteredCode.equals(code);
    if (isValid) {
      if (Long.parseLong(ttl) < System.currentTimeMillis()) {
        // expired
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
            context.form().setError("emailTOTPCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
      } else {
        // valid
        if (!context.getUser().isEmailVerified()) {
          context.getUser().setEmailVerified(true);
        }
        context.success();
      }
    } else {
      // Code is invalid
      if (remainingAttempts > 0) {
        authSession.setAuthNote(AUTH_NOTE_REMAINING_RETRIES, Integer.toString(remainingAttempts - 1));

        // Inform user of the remaining attempts
        context.failureChallenge(
            AuthenticationFlowError.INVALID_CREDENTIALS,
            context.form()
                .setAttribute("realm", context.getRealm())
                .setError("emailTOTPCodeInvalid", Integer.toString(remainingAttempts))
                .createForm(TOTP_FORM));
      } else {
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
      }
    }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user.getEmail() != null;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void close() {
  }

  private int getMaxRetries(AuthenticatorConfigModel config) {
    int maxRetries = Integer.parseInt(
        config.getConfig()
            .getOrDefault(
                EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RETRIES,
                "3"));
    return maxRetries;
  }

  private String getCode(AuthenticatorConfigModel config) {
    int length = Integer.parseInt(config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_LENGTH));
    Boolean allowUppercase = Boolean.parseBoolean(
        config.getConfig()
            .getOrDefault(
                EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_UPPERCASE,
                "true"));
    Boolean allowLowercase = Boolean.parseBoolean(
        config.getConfig()
            .getOrDefault(
                EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_LOWERCASE,
                "true"));
    Boolean allowNumbers = Boolean.parseBoolean(
        config.getConfig()
            .getOrDefault(
                EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_NUMBERS,
                "true"));

    StringBuilder sb = new StringBuilder();

    if (allowUppercase) {
      sb.append(ALPHA_UPPER);
    }
    if (allowLowercase) {
      sb.append(ALPHA_LOWER);
    }
    if (allowNumbers) {
      sb.append(NUM);
    }

    // if the string builder is empty allow all charsets as default
    if (sb.length() == 0) {
      sb.append(ALPHA_UPPER)
          .append(ALPHA_LOWER)
          .append(NUM);
    }

    char[] symbols = sb.toString().toCharArray();
    return SecretGenerator
        .getInstance()
        .randomString(length, symbols);
  }

}

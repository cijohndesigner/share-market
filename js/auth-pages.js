
/*
 * CJ Cruz Trade Tracker — Authentication
 * Signup: username + password + confirm password
 * Login: username + password
 * Approval: pending / approved / rejected / suspended
 *
 * Supabase Auth internally maps usernames to synthetic email addresses.
 * Password resets for these accounts must be administrator-managed.
 * Never expose a Supabase service-role key in browser JavaScript.
 */

(function () {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const client = () => window.CJ_SUPABASE;

  function msg(text, type = "error") {
    const el = $("[data-auth-message]");
    if (!el) return;

    el.textContent = text;
    el.className = "auth-message show " + type;
    el.setAttribute("role", "status");
  }

  function normalizeUsername(value) {
    const username = String(value || "").trim().toLowerCase();

    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      throw new Error(
        "Username must be 3–32 characters using letters, numbers, dots, underscores or hyphens."
      );
    }

    if (!window.CJ_AUTH_EMAIL_DOMAIN) {
      throw new Error(
        "Missing CJ_AUTH_EMAIL_DOMAIN in js/supabase-config.js."
      );
    }

    return username;
  }

  function usernameEmail(username) {
    return username + "@" +
      String(window.CJ_AUTH_EMAIL_DOMAIN).trim().toLowerCase();
  }

  function currentPage() {
    return window.location.pathname
      .split("/")
      .filter(Boolean)
      .pop() || "index.html";
  }

  async function getApprovalStatus(userId) {
    const { data, error } = await client()
      .from("member_access")
      .select("status")
      .eq("user_id", userId)
      .maybeSingle();

    if (error) throw error;

    return String(data?.status || "pending")
      .trim()
      .toLowerCase();
  }

  async function savePendingAccess(userId, username) {
    const { error } = await client()
      .from("member_access")
      .insert({
        user_id: userId,
        username,
        status: "pending",
        updated_at: new Date().toISOString()
      });

    if (error) {
      if (
        error.code === "23505" ||
        /duplicate key|already exists/i.test(error.message || "")
      ) {
        throw new Error(
          "This account already has an approval record. Ask the administrator to check member_access."
        );
      }

      throw new Error(
        "The authentication account was created, but its pending approval record could not be saved. Check the member_access INSERT policy. Details: " +
        error.message
      );
    }
  }

  async function handleSignup(auth, formData) {
    const username = normalizeUsername(formData.get("username"));
    const password = String(formData.get("password") || "");
    const confirmPassword = String(
      formData.get("confirmPassword") || ""
    );

    if (password.length < 10) {
      throw new Error("Use a password with at least 10 characters.");
    }

    if (password !== confirmPassword) {
      throw new Error("The passwords do not match.");
    }

    const { data, error } = await auth.auth.signUp({
      email: usernameEmail(username),
      password,
      options: {
        data: {
          username,
          display_name: username,
          full_name: username
        }
      }
    });

    if (error) {
      const reason = String(error.message || "").toLowerCase();

      if (
        reason.includes("already registered") ||
        reason.includes("already been registered") ||
        reason.includes("user already exists")
      ) {
        throw new Error(
          "This username may already exist. Ask the administrator to check Supabase Authentication → Users before trying again."
        );
      }

      throw error;
    }

    if (!data?.user) {
      throw new Error("Supabase did not return a user. Please try again.");
    }

    if (!data.session) {
      msg(
        "Supabase created the account but did not start a session, so the pending approval record could not be saved. Do not register again. Ask the administrator to check this account and the Confirm email setting."
      );
      return;
    }

    try {
      await savePendingAccess(data.user.id, username);
    } catch (e) {
      await auth.auth.signOut();
      throw e;
    }

    await auth.auth.signOut();

    msg(
      "Account created successfully. Your status is Pending until the administrator approves it.",
      "success"
    );

    window.setTimeout(() => {
      window.location.href = "auth-login.html";
    }, 1800);
  }

  async function handleLogin(auth, formData) {
    const username = normalizeUsername(formData.get("username"));
    const password = String(formData.get("password") || "");

    if (!password) {
      throw new Error("Enter your password.");
    }

    const { data, error } = await auth.auth.signInWithPassword({
      email: usernameEmail(username),
      password
    });

    if (error) {
      const reason = String(error.message || "").toLowerCase();

      if (reason.includes("email not confirmed")) {
        throw new Error(
          "This account is not confirmed in Supabase. Ask the administrator to review the existing account."
        );
      }

      if (reason.includes("invalid login credentials")) {
        throw new Error(
          "Username or password is incorrect. Check the exact username and password."
        );
      }

      throw new Error(error.message || "Sign-in failed.");
    }

    let status;

    try {
      status = await getApprovalStatus(data.user.id);
    } catch (e) {
      await auth.auth.signOut();

      throw new Error(
        "Could not verify member approval. Check the member_access SELECT policy. " +
        (e?.message || "")
      );
    }

    if (status !== "approved") {
      await auth.auth.signOut();

      const messages = {
        pending: "Your account is waiting for administrator approval.",
        rejected: "Your access request was rejected. Contact the administrator.",
        suspended: "Your account is suspended. Contact the administrator."
      };

      throw new Error(
        messages[status] || "This account is not approved for access."
      );
    }

    window.location.href = "dashboard.html";
  }

  function handleForgotPassword(formData) {
    const username = normalizeUsername(formData.get("username"));

    msg(
      "Password resets for username-based accounts are managed by the CJ Cruz administrator. Contact the administrator and verify your identity. Never share your current password.",
      "success"
    );
  }

  async function handleUpdatePassword(auth, formData) {
    const password = String(formData.get("password") || "");
    const confirmPassword = String(
      formData.get("confirmPassword") || ""
    );

    if (password.length < 10) {
      throw new Error("Use a password with at least 10 characters.");
    }

    if (password !== confirmPassword) {
      throw new Error("The passwords do not match.");
    }

    const { error } = await auth.auth.updateUser({ password });

    if (error) throw error;

    await auth.auth.signOut();

    msg("Password updated successfully. You can now sign in.", "success");

    window.setTimeout(() => {
      window.location.href = "auth-login.html";
    }, 1800);
  }

  async function submit(form) {
    const auth = client();

    if (!auth) {
      msg(
        "Supabase is not configured. Check js/supabase-config.js and its publishable key."
      );
      return;
    }

    const page = currentPage();
    const formData = new FormData(form);
    const button = form.querySelector('button[type="submit"]');

    if (button) {
      button.disabled = true;
      button.dataset.originalText ||= button.textContent;
      button.textContent = "Please wait…";
    }

    try {
      switch (page) {
        case "auth-signup.html":
          await handleSignup(auth, formData);
          break;

        case "auth-login.html":
          await handleLogin(auth, formData);
          break;

        case "auth-forgot-password.html":
          handleForgotPassword(formData);
          break;

        case "auth-update-password.html":
          await handleUpdatePassword(auth, formData);
          break;

        default:
          throw new Error(
            "Unsupported authentication page: " + page +
            ". Check the page filename and script path."
          );
      }
    } catch (e) {
      const message = String(
        e?.message || "Something went wrong. Please try again."
      );

      if (
        /email signups are disabled|signups not allowed|email provider.*disabled/i.test(message)
      ) {
        msg(
          "Enable the Email provider in Supabase → Authentication → Sign In / Providers. Keep Confirm email OFF for this username-based setup."
        );
      } else {
        msg(message);
      }
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent =
          button.dataset.originalText || "Continue";
      }
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const form = $("[data-auth-form]");

    if (!form) return;

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submit(form);
    });
  });
})();

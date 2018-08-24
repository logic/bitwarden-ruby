#
# Copyright (c) 2017 joshua stein <jcs@jcs.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

require 'net/smtp'

module Rubywarden
  module Routing
    module Api
      def self.registered(app)
        app.namespace BASE_URL do
          post "/accounts/prelogin" do
            need_params(:email) do |p|
              return validation_error("#{p} cannot be blank")
            end

            kdf_type = User::DEFAULT_KDF_TYPE
            iterations = Bitwarden::KDF::DEFAULT_ITERATIONS[kdf_type]

            if u = User.find_by_email(params[:email])
              iterations = u.kdf_iterations
              kdf_type = Bitwarden::KDF::TYPES[u.kdf_type]
            end

            {
              "Kdf" => Bitwarden::KDF::TYPE_IDS[kdf_type],
              "KdfIterations" => iterations,
            }.to_json
          end

          # create a new user
          post "/accounts/register" do
            content_type :json

            if !ALLOW_SIGNUPS
              return validation_error("Signups are not permitted")
            end

            need_params(:masterpasswordhash, :kdf, :kdfiterations) do |p|
              return validation_error("#{p} cannot be blank")
            end

            if !params[:email].to_s.match(/^.+@.+\..+$/)
              return validation_error("Invalid e-mail address")
            end

            if !params[:key].to_s.match(/^0\..+\|.+/)
              return validation_error("Invalid key")
            end

            if params.key?(:keys) && !params[:keys][:encryptedPrivateKey].to_s.match(/^2\..+\|.+/)
              return validation_error("Invalid key")
            end

            kdf_type = Bitwarden::KDF::TYPES[params[:kdf].to_i]
            if !kdf_type
              return validation_error("invalid kdf type")
            end

            if !Bitwarden::KDF::ITERATION_RANGES[kdf_type].
            include?(params[:kdfiterations].to_i)
              return validation_error("invalid kdf iterations")
            end

            begin
              Bitwarden::CipherString.parse(params[:key])
            rescue Bitwarden::InvalidCipherString
              return validation_error("Invalid key")
            end

            User.transaction do
              params[:email].downcase!

              if User.find_by_email(params[:email])
                return validation_error("E-mail is already in use")
              end

              u = User.new
              u.email = params[:email]
              u.password_hash = params[:masterpasswordhash]
              u.password_hint = params[:masterpasswordhint]
              u.key = params[:key]
              if params.key? :keys
                u.public_key = params[:keys][:publicKey]
                u.private_key = params[:keys][:encryptedPrivateKey]
              end
              u.kdf_type = Bitwarden::KDF::TYPE_IDS[kdf_type]
              u.kdf_iterations = params[:kdfiterations]

              # is this supposed to come from somewhere?
              u.culture = "en-US"

              # i am a fair and just god
              u.premium = true

              if !u.save
                return validation_error("User save failed")
              end

              headers "access-control-allow-origin" => "*"
              ""
            end
          end

          # send a password hint to a registered user
          post "/accounts/password-hint" do
            if !settings.smtp or !settings.smtp_from
              return validation_error("SMTP server not configured properly")
            end

            unless params[:email].to_s.match?(/^.+@.+\..+$/)
              return validation_error("Invalid e-mail address")
            end

            u = User.find_by_email(params["email"])
            if u
              Thread.new do
                begin
                  smtp = Net::SMTP.new(settings.smtp[:address], settings.smtp[:port])
                  if settings.smtp[:tls]
                    smtp.enable_tls
                  elsif settings.smtp[:starttls]
                    smtp.enable_starttls
                  end
                  smtp.start(settings.smtp.fetch(:helo, 'localhost'),
                             settings.smtp[:user],
                             settings.smtp[:secret],
                             settings.smtp[:authtype]) do |server|
                    hint = if u.password_hint
                             "It is: #{u.password_hint}"
                           else
                             "Unfortunately, you didn't set a password hint."
                           end
                    message = <<~MESSAGE
                      From: #{settings.smtp_from}
                      To: #{u.email}
                      Subject: bitwarden master password hint

                      Someone (possibly you!) at the IP address #{request.ip} requested your
                      master password hint for #{request.host}.

                      #{hint}

                      If you didn't request your hint, you can safely ignore this email.
                    MESSAGE
                    smtp.send_message message, settings.smtp_from, u.email
                  end
                rescue => e
                  logger.error e
                end
              end
            end
            {}.to_json
          end

          # fetch profile and ciphers
          get "/sync" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            {
              "Profile" => d.user.to_hash,
              "Folders" => d.user.folders.map{|f| f.to_hash },
              "Ciphers" => d.user.ciphers.map{|c| c.to_hash },
              "Domains" => {
                "EquivalentDomains" => nil,
                "GlobalEquivalentDomains" => [],
                "Object" => "domains",
              },
              "Object" => "sync",
            }.to_json
          end

          # Used by the web vault to update the private and public keys if the user doesn't have one.
          post "/accounts/keys" do
            content_type :json
            # Needed by the web vault for EVERY response
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            if !params[:encryptedprivatekey].to_s.match(/^2\..+\|.+/)
              return validation_error("Invalid key")
            end

            d.user.private_key = params[:encryptedprivatekey]
            d.user.public_key = params[:publickey]

            {
              "Id" => d.user_uuid,
              "Name" => d.user.name,
              "Email" => d.user.email,
              "EmailVerified" => d.user.email_verified,
              "Premium" => d.user.premium,
              "MasterPasswordHint" => d.user.password_hint,
              "Culture" => d.user.culture,
              "TwoFactorEnabled" => d.user.totp_secret,
              "Key" => d.user.key,
              "PrivateKey" => d.user.private_key,
              "SecurityStamp" => d.user.security_stamp,
              "Organizations" => "[]",
              "Object" => "profile",
            }.to_json
          end

          # Used by the web vaul to connect and load the user profile/datas
          get "/accounts/profile" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            {
              "Id" => d.user_uuid,
              "Name" => d.user.name,
              "Email" => d.user.email,
              "EmailVerified" => d.user.email_verified,
              "Premium" => d.user.premium,
              "MasterPasswordHint" => d.user.password_hint,
              "Culture" => d.user.culture,
              "TwoFactorEnabled" => d.user.totp_secret,
              "Key" => d.user.key,
              "PrivateKey" => d.user.private_key,
              "SecurityStamp" => d.user.security_stamp,
              "Organizations" => "[]",
              "Object" => "profile",
            }.to_json
          end

          # Used to update masterpassword
          post "/accounts/password" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            need_params(:key, :masterpasswordhash, :newmasterpasswordhash) do |p|
              return validation_error("#{p} cannot be blank")
            end

            if !params[:key].to_s.match(/^0\..+\|.+/)
              return validation_error("Invalid key")
            end

            begin
              Bitwarden::CipherString.parse(params[:key])
            rescue Bitwarden::InvalidCipherString
              return validation_error("Invalid key")
            end

            if d.user.password_hash == params[:masterpasswordhash]
              d.user.key=params[:key]
              d.user.password_hash=params[:newmasterpasswordhash]
            else
              return validation_error("Wrong current password")
            end

            User.transaction do
              if !d.user.save
                return validation_error("Unknown error")
              end
            end
          ""
          end

          # Used to update email
          post "/accounts/email-token" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            validation_error("Not implemented yet")
          end

          #
          # ciphers
          #

          get "/ciphers" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end
            {
              "Data" => d.user.ciphers.map{|f| f.to_hash},
              "Object" => "list",
            }.to_json
          end

          # Import from keepass or others via web vault
          post "/ciphers/import" do
            content_type :json
            response['access-control-allow-origin'] = '*'

            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end
            return validation_error("import tool not implemented yet")
          end

          # create a new cipher
          post "/ciphers" do
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            need_params(:type, :name) do |p|
              return validation_error("#{p} cannot be blank")
            end

            begin
              Bitwarden::CipherString.parse(params[:name])
            rescue Bitwarden::InvalidCipherString
              return validation_error("Invalid name")
            end

            if !params[:folderid].blank?
              if !Folder.find_by_user_uuid_and_uuid(d.user_uuid, params[:folderid])
                return validation_error("Invalid folder")
              end
            end

            c = Cipher.new
            c.user_uuid = d.user_uuid
            c.update_from_params(params)

            Cipher.transaction do
              if !c.save
                return validation_error("error saving")
              end

              c.to_hash.merge({
                "Edit" => true,
              }).to_json
            end
          end

          get "/ciphers/:uuid" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            c = nil

            if !(c = Cipher.find_by_uuid(params[:uuid]))
              return validation_error("invalid cipher")
            end
            c.to_hash.merge({
                "Edit" => true,
            }).to_json
          end

          # update a cipher via web vault
          post "/ciphers/:uuid" do
            update_cipher()
          end

          # update a cipher
          put "/ciphers/:uuid" do
            update_cipher()
          end

          # delete a cipher
          delete "/ciphers/:uuid" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            c = nil
            if params[:uuid].blank? ||
            !(c = Cipher.find_by_user_uuid_and_uuid(d.user_uuid, params[:uuid]))
              return validation_error("invalid cipher")
            end

            c.destroy

            ""
          end

          #
          # folders
          #

          # retrieve folder
          get "/folders" do
            content_type :json
            response['access-control-allow-origin'] = '*'
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end
            {
              "Data" => d.user.folders.map{|f| f.to_hash},
              "Object" => "list",
            }.to_json
          end

          # create a new folder
          post "/folders" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            need_params(:name) do |p|
              return validation_error("#{p} cannot be blank")
            end

            begin
              Bitwarden::CipherString.parse(params[:name])
            rescue
              return validation_error("Invalid name")
            end

            f = Folder.new
            f.user_uuid = d.user_uuid
            f.update_from_params(params)

            Folder.transaction do
              if !f.save
                return validation_error("error saving")
              end

              f.to_hash.to_json
            end
          end

          # rename a folder
          put "/folders/:uuid" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            f = nil
            if params[:uuid].blank? ||
            !(f = Folder.find_by_user_uuid_and_uuid(d.user_uuid, params[:uuid]))
              return validation_error("invalid folder")
            end

            need_params(:name) do |p|
              return validation_error("#{p} cannot be blank")
            end

            begin
              Bitwarden::CipherString.parse(params[:name])
            rescue
              return validation_error("Invalid name")
            end

            f.update_from_params(params)

            Folder.transaction do
              if !f.save
                return validation_error("error saving")
              end

              f.to_hash.to_json
            end
          end

          # delete a folder
          delete "/folders/:uuid" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            f = nil
            if params[:uuid].blank? ||
            !(f = Folder.find_by_user_uuid_and_uuid(d.user_uuid, params[:uuid]))
              return validation_error("invalid folder")
            end

            f.destroy

            ""
          end

          #
          # device push tokens
          #

          put "/devices/identifier/:uuid/clear-token" do
            # XXX: for some reason, the iOS app doesn't send an Authorization header
            # for this
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            d.push_token = nil

            Device.transaction do
              if !d.save
                return validation_error("error saving")
              end

              ""
            end
          end

          put "/devices/identifier/:uuid/token" do
            d = device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            d.push_token = params[:pushtoken]

            Device.transaction do
              if !d.save
                return validation_error("error saving")
              end

              ""
            end
          end

          #
          # Organizations
          #

          post "/organizations" do
            d= device_from_bearer
            if !d
              return validation_error("invalid bearer")
            end

            return validation_error("Organizations not implemented yet")
          end

          #
          # Collections
          #

          get "/collections" do
            response['access-control-allow-origin'] = '*'
            {"Data" => [],"Object" => "list"}.to_json
          end
        end
      end
    end
  end
end

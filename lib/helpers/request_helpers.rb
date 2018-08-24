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

module Rubywarden
  module RequestHelpers
    def device_from_bearer
      if m = (request.env["HTTP_AUTHORIZATION"].to_s.match(/^Bearer (.+)/) || request.env["HTTP_CONTENT_LANGUAGE"].to_s.match(/^Bearer (.+)/))
        token = m[1]
        if (d = Device.find_by_access_token(token))
          if d.token_expires_at >= Time.now
            return d
          end
        end
      end

      nil
    end

    def need_params(*ps)
      ps.each do |p|
        if params[p].to_s.blank?
          yield(p)
        end
      end
    end

    def validation_error(msg)
      [ 400, {
        "ValidationErrors" => { "" => [
          msg,
        ]},
        "Object" => "error",
      }.to_json ]
    end

    def delete_cipher app:, uuid:
      d = device_from_bearer
      if !d
        halt validation_error("invalid bearer")
      end

      c = nil
      if uuid.blank? || !(c = Cipher.find_by_user_uuid_and_uuid(d.user_uuid, uuid))
        halt validation_error("invalid cipher")
      end
      c.destroy
      ""
    end # delete_cipher

    def update_cipher()
      response['access-control-allow-origin'] = '*'
      d = device_from_bearer
      if !d
        return validation_error("invalid bearer")
      end

      c = nil
      if params[:uuid].blank? ||
      !(c = Cipher.find_by_user_uuid_and_uuid(d.user_uuid, params[:uuid]))
        return validation_error("invalid cipher")
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
  end
end

module Clearance
  module PasswordStrategies
    module SHA1
      require 'digest/sha1'
      extend ActiveSupport::Concern

      def authenticated?(password)
        # encrypted_password == encrypt(password)
        encrypted_password == password_digest(password, salt)
      end

      def password=(new_password)
        @password = new_password
        initialize_salt_if_necessary

        if new_password.present?
          self.encrypted_password = encrypt(new_password)
        end
      end

      private

      def secure_digest(*args)
        Digest::SHA1.hexdigest(args.flatten.join('--'))
      end

      def password_digest(password, salt)
        begin
          digest = REST_AUTH_SITE_KEY
          REST_AUTH_DIGEST_STRETCHES.times do
            digest = secure_digest(digest, salt, password, REST_AUTH_SITE_KEY)
          end
          digest
        rescue ArgumentError
          raise "site_keys initializer not initialized."
        end
      end

      def encrypt(string)
        generate_hash "--#{salt}--#{string}--"
      end

      def generate_hash(string)
        Digest::SHA1.hexdigest(string).encode "UTF-8"
      end

      def initialize_salt_if_necessary
        if salt.blank?
          self.salt = generate_salt
        end
      end

      def generate_salt
        SecureRandom.hex(20).encode("UTF-8")
      end
    end
  end
end

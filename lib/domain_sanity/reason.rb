# frozen_string_literal: true

module DomainSanity
  # A single, structured reason a subject failed validation.
  #
  # `code` is a stable Symbol meant for programmatic branching (it does not
  # change when the wording of a message is tweaked). `message` is the
  # human-readable explanation. `label` is the specific offending DNS label
  # when one applies (e.g. a label that is too long or malformed), and nil
  # otherwise.
  #
  # Reason#to_s returns the message, so an array of reasons still interpolates
  # and joins into readable text, while callers that need to react in code can
  # switch on `code`.
  Reason = Struct.new(:code, :message, :label, keyword_init: true) do
    def to_s
      message
    end
  end
end

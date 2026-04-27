module Api
  class CodeAnalysisApiController < ApiController
    before_action :require_api_admin!

    MAX_FILE_SIZE = 1.megabyte

    # POST /api/:key/code-analysis
    # Accepts multipart: source_file=<binary>
    # Or JSON/form: content=<text>&filename=<name>
    # Note: OllamaService may take up to 15 minutes to respond
    def analyze
      if params[:source_file].respond_to?(:read)
        file = params[:source_file]
        if file.size > MAX_FILE_SIZE
          render json: { error: "File too large (max 1 MB)" }, status: :unprocessable_entity
          return
        end
        content  = file.read.force_encoding("UTF-8").scrub
        filename = file.original_filename
        ext      = File.extname(filename).delete_prefix(".")
      elsif params[:content].present?
        content  = params[:content].to_s.force_encoding("UTF-8").scrub
        filename = params[:filename].presence || "upload.txt"
        ext      = File.extname(filename).delete_prefix(".")
      else
        render json: { error: "Provide source_file (multipart) or content + filename" },
               status: :unprocessable_entity
        return
      end

      result = OllamaService.analyze_code(content, ext, filename)
      if result.is_a?(Hash) && result[:error]
        render json: { error: result[:error] }, status: :service_unavailable
      else
        render json: { result: result }
      end
    end
  end
end

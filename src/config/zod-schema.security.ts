import { z } from "zod";

export const externalContentSecuritySchema = z
	.object({
		enabled: z.boolean().optional(),
		action: z.enum(["flag", "block", "confirm"]).optional(),
		threshold: z.enum(["low", "medium", "high"]).optional(),
		alertSession: z.string().optional(),
		sources: z
			.object({
				webFetch: z.boolean().optional(),
				browser: z.boolean().optional(),
				email: z.boolean().optional(),
				webhooks: z.boolean().optional(),
				feeds: z.boolean().optional(),
				files: z.boolean().optional(),
			})
			.optional(),
		untrustedPaths: z.array(z.string()).optional(),
	})
	.optional();

export const securitySchema = z
	.object({
		externalContent: externalContentSecuritySchema,
	})
	.optional();

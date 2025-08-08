// CHECKSTYLE:OFF

package io.jenkins.plugins.sample;

import org.jvnet.localizer.Localizable;
import org.jvnet.localizer.ResourceBundleHolder;
import org.kohsuke.accmod.Restricted;


/**
 * Generated localization support class.
 * 
 */
@SuppressWarnings({
    "",
    "PMD",
    "all"
})
@Restricted(org.kohsuke.accmod.restrictions.NoExternalUse.class)
public class Messages {

    /**
     * The resource bundle reference
     * 
     */
    private final static ResourceBundleHolder holder = ResourceBundleHolder.get(Messages.class);

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.errors.missingName}:
     * {@code Please set a name}.
     * 
     * @return
     *     {@code Please set a name}
     */
    public static String HelloWorldBuilder_DescriptorImpl_errors_missingName() {
        return holder.format("HelloWorldBuilder.DescriptorImpl.errors.missingName");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.errors.missingName}:
     * {@code Please set a name}.
     * 
     * @return
     *     {@code Please set a name}
     */
    public static Localizable _HelloWorldBuilder_DescriptorImpl_errors_missingName() {
        return new Localizable(holder, "HelloWorldBuilder.DescriptorImpl.errors.missingName");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.warnings.reallyFrench}:
     * {@code Are you actually French?}.
     * 
     * @return
     *     {@code Are you actually French?}
     */
    public static String HelloWorldBuilder_DescriptorImpl_warnings_reallyFrench() {
        return holder.format("HelloWorldBuilder.DescriptorImpl.warnings.reallyFrench");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.warnings.reallyFrench}:
     * {@code Are you actually French?}.
     * 
     * @return
     *     {@code Are you actually French?}
     */
    public static Localizable _HelloWorldBuilder_DescriptorImpl_warnings_reallyFrench() {
        return new Localizable(holder, "HelloWorldBuilder.DescriptorImpl.warnings.reallyFrench");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.warnings.tooShort}: {@code
     * Isn't the name too short?}.
     * 
     * @return
     *     {@code Isn't the name too short?}
     */
    public static String HelloWorldBuilder_DescriptorImpl_warnings_tooShort() {
        return holder.format("HelloWorldBuilder.DescriptorImpl.warnings.tooShort");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.warnings.tooShort}: {@code
     * Isn't the name too short?}.
     * 
     * @return
     *     {@code Isn't the name too short?}
     */
    public static Localizable _HelloWorldBuilder_DescriptorImpl_warnings_tooShort() {
        return new Localizable(holder, "HelloWorldBuilder.DescriptorImpl.warnings.tooShort");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.DisplayName}: {@code Say
     * hello world}.
     * 
     * @return
     *     {@code Say hello world}
     */
    public static String HelloWorldBuilder_DescriptorImpl_DisplayName() {
        return holder.format("HelloWorldBuilder.DescriptorImpl.DisplayName");
    }

    /**
     * Key {@code HelloWorldBuilder.DescriptorImpl.DisplayName}: {@code Say
     * hello world}.
     * 
     * @return
     *     {@code Say hello world}
     */
    public static Localizable _HelloWorldBuilder_DescriptorImpl_DisplayName() {
        return new Localizable(holder, "HelloWorldBuilder.DescriptorImpl.DisplayName");
    }

}
